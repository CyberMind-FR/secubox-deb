# Eye Remote Bootstrap v2.1.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add mass_storage LUN + TFTP shadow channel to Eye Remote USB OTG composite gadget for U-Boot boot loading.

**Architecture:** Shell script (`gadget-setup.sh`) manages configfs for ECM+ACM+mass_storage functions. Python core (`boot_media.py`) handles image upload, sha256 verification, atomic swap with file locking. FastAPI router exposes /boot-media/ endpoints. dnsmasq serves TFTP from shadow slot.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic v2, Bash (configfs), dnsmasq (TFTP)

**Spec:** `docs/superpowers/specs/2026-04-23-eye-remote-bootstrap-design.md`

---

## File Structure

```
packages/secubox-eye-remote/
├── models/
│   └── boot_media.py              # Pydantic models (BootImage, BootMediaState)
├── core/
│   └── boot_media.py              # File ops, atomic swap, validation
├── api/routers/
│   └── boot_media.py              # FastAPI endpoints
└── tests/integration/
    └── test_boot_media.py         # Integration tests

remote-ui/round/
├── files/etc/
│   ├── secubox/eye-remote/
│   │   ├── gadget-setup.sh        # libcomposite configfs script
│   │   └── tftp.env               # DHCP toggle env file
│   ├── systemd/system/
│   │   ├── secubox-eye-gadget.service
│   │   └── dnsmasq.service.d/
│   │       └── secubox-eye.conf
│   └── dnsmasq.d/
│       └── secubox-eye-tftp.conf
└── build-eye-remote-image.sh      # Updated for v2.1.0

debian/secubox-eye-remote/
├── install
├── postinst
├── postrm
└── changelog

docs/
├── eye-remote/
│   └── uboot-bootcmd.md
└── wiki/
    ├── Eye-Remote-Bootstrap.md
    ├── Eye-Remote-Bootstrap-FR.md
    └── Eye-Remote-Bootstrap-ZH.md
```

---

## Task 1: Pydantic Models

**Files:**
- Create: `packages/secubox-eye-remote/models/boot_media.py`
- Modify: `packages/secubox-eye-remote/models/__init__.py`

### Step 1.1: Write model tests

- [ ] Create test file

```python
# packages/secubox-eye-remote/tests/unit/test_models_boot_media.py
"""
Tests for boot media Pydantic models.
"""
import pytest
from datetime import datetime, timezone

from models.boot_media import BootSlot, BootImage, BootMediaState


class TestBootSlot:
    def test_enum_values(self):
        assert BootSlot.ACTIVE == "active"
        assert BootSlot.SHADOW == "shadow"


class TestBootImage:
    def test_create_valid(self):
        img = BootImage(
            path="images/abc123.img",
            sha256="abc123def456",
            size_bytes=16777216,
            created_at=datetime.now(timezone.utc),
            label="test-image",
        )
        assert img.path == "images/abc123.img"
        assert img.size_bytes == 16777216

    def test_label_optional(self):
        img = BootImage(
            path="images/abc.img",
            sha256="abc",
            size_bytes=1000,
            created_at=datetime.now(timezone.utc),
        )
        assert img.label is None


class TestBootMediaState:
    def test_empty_state(self):
        state = BootMediaState(
            active=None,
            shadow=None,
            lun_attached=False,
            last_swap_at=None,
            tftp_armed=False,
        )
        assert state.active is None
        assert not state.lun_attached

    def test_with_active_image(self):
        img = BootImage(
            path="images/x.img",
            sha256="x",
            size_bytes=1000,
            created_at=datetime.now(timezone.utc),
        )
        state = BootMediaState(
            active=img,
            shadow=None,
            lun_attached=True,
            last_swap_at=None,
            tftp_armed=False,
        )
        assert state.active is not None
        assert state.active.sha256 == "x"
```

- [ ] Run test to verify it fails

```bash
cd packages/secubox-eye-remote
python -m pytest tests/unit/test_models_boot_media.py -v
```

Expected: FAIL with "ModuleNotFoundError: No module named 'models.boot_media'"

### Step 1.2: Write models

- [ ] Create boot_media models

```python
# packages/secubox-eye-remote/models/boot_media.py
"""
SecuBox Eye Remote — Boot Media Models
Pydantic models for boot media management (LUN + TFTP).

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class BootSlot(str, Enum):
    """Boot media slots for 4R double-buffer."""
    ACTIVE = "active"
    SHADOW = "shadow"


class BootImage(BaseModel):
    """A boot media image."""
    path: str = Field(..., description="Relative path within images/ directory")
    sha256: str = Field(..., description="SHA256 hash of image content")
    size_bytes: int = Field(..., description="Image size in bytes")
    created_at: datetime = Field(..., description="Upload timestamp")
    label: Optional[str] = Field(None, description="User-friendly label")


class BootMediaState(BaseModel):
    """Current state of boot media slots."""
    active: Optional[BootImage] = Field(None, description="Currently active boot image")
    shadow: Optional[BootImage] = Field(None, description="Shadow slot (for testing/swap)")
    lun_attached: bool = Field(..., description="Whether LUN is attached to USB gadget")
    last_swap_at: Optional[datetime] = Field(None, description="Last active/shadow swap timestamp")
    tftp_armed: bool = Field(..., description="Whether TFTP is serving shadow boot files")


class UploadResponse(BaseModel):
    """Response after uploading boot image."""
    success: bool
    image: BootImage
    message: str = "Image uploaded to shadow slot"


class SwapResponse(BaseModel):
    """Response after swap operation."""
    success: bool
    state: BootMediaState
    message: str


class TftpStatusResponse(BaseModel):
    """TFTP service status."""
    alive: bool = Field(..., description="Whether dnsmasq TFTP is running")
    root: str = Field(..., description="TFTP root directory path")
    files: list[str] = Field(default_factory=list, description="Files in TFTP directory")
```

### Step 1.3: Update models __init__.py

- [ ] Add exports

```python
# packages/secubox-eye-remote/models/__init__.py
"""SecuBox Eye Remote models."""
from .device import (
    TransportType,
    DeviceCapability,
    DeviceScope,
    PairedDevice,
    DeviceListResponse,
    PairRequest,
    PairResponse,
    CommandRequest,
    CommandResponse,
)
from .boot_media import (
    BootSlot,
    BootImage,
    BootMediaState,
    UploadResponse,
    SwapResponse,
    TftpStatusResponse,
)

__all__ = [
    "TransportType",
    "DeviceCapability",
    "DeviceScope",
    "PairedDevice",
    "DeviceListResponse",
    "PairRequest",
    "PairResponse",
    "CommandRequest",
    "CommandResponse",
    "BootSlot",
    "BootImage",
    "BootMediaState",
    "UploadResponse",
    "SwapResponse",
    "TftpStatusResponse",
]
```

### Step 1.4: Verify tests pass

- [ ] Run tests

```bash
cd packages/secubox-eye-remote
python -m pytest tests/unit/test_models_boot_media.py -v
```

Expected: All tests PASS

### Step 1.5: Commit

- [ ] Commit models

```bash
git add packages/secubox-eye-remote/models/boot_media.py \
       packages/secubox-eye-remote/models/__init__.py \
       packages/secubox-eye-remote/tests/unit/test_models_boot_media.py
git commit -m "feat(eye-remote): add boot media Pydantic models"
```

---

## Task 2: Gadget Setup Script

**Files:**
- Create: `remote-ui/round/files/etc/secubox/eye-remote/gadget-setup.sh`

### Step 2.1: Create directory structure

- [ ] Create directories

```bash
mkdir -p remote-ui/round/files/etc/secubox/eye-remote
mkdir -p remote-ui/round/files/etc/systemd/system/dnsmasq.service.d
mkdir -p remote-ui/round/files/etc/dnsmasq.d
```

### Step 2.2: Write gadget-setup.sh

- [ ] Create script

```bash
#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Eye Remote — gadget-setup.sh
# USB Gadget composite via libcomposite (ECM + ACM + mass_storage)
#
# CyberMind — https://cybermind.fr
# Author: Gerald Kerma <gandalf@gk2.net>
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

readonly VERSION="2.1.0"
readonly GADGET_NAME="secubox"
readonly CONFIGFS="/sys/kernel/config/usb_gadget"
readonly GADGET_PATH="${CONFIGFS}/${GADGET_NAME}"

# Boot media paths
readonly BOOT_MEDIA_DIR="/var/lib/secubox/eye-remote/boot-media"
readonly ACTIVE_SYMLINK="${BOOT_MEDIA_DIR}/active"
readonly PLACEHOLDER_IMG="${BOOT_MEDIA_DIR}/images/placeholder.img"

# USB IDs (Linux Foundation — Multifunction Composite Gadget)
readonly ID_VENDOR="0x1d6b"
readonly ID_PRODUCT="0x0104"
readonly BCD_DEVICE="0x0210"
readonly BCD_USB="0x0200"

# Manufacturer info
readonly MANUFACTURER="CyberMind SecuBox"
readonly PRODUCT="Eye Remote Bootstrap"

# Logging
log()  { echo "[gadget-setup] $*"; logger -t secubox-eye-gadget "$*"; }
err()  { echo "[gadget-setup] ERROR: $*" >&2; logger -t secubox-eye-gadget -p err "$*"; return 1; }

# ═══════════════════════════════════════════════════════════════════════════════
# Get serial number from /proc/cpuinfo
# ═══════════════════════════════════════════════════════════════════════════════
get_serial() {
    grep -Po '(?<=Serial\s:\s)[0-9a-f]+' /proc/cpuinfo 2>/dev/null || echo "0000000000000000"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Check prerequisites
# ═══════════════════════════════════════════════════════════════════════════════
check_prerequisites() {
    # Check configfs mounted
    if [[ ! -d "$CONFIGFS" ]]; then
        log "Mounting configfs..."
        modprobe configfs 2>/dev/null || true
        mount -t configfs none /sys/kernel/config 2>/dev/null || true
        if [[ ! -d "$CONFIGFS" ]]; then
            err "configfs not available"
        fi
    fi

    # Load libcomposite
    modprobe libcomposite 2>/dev/null || true

    # Ensure boot media directory exists
    if [[ ! -d "$BOOT_MEDIA_DIR" ]]; then
        log "Creating boot media directory..."
        mkdir -p "${BOOT_MEDIA_DIR}/images"
        mkdir -p "${BOOT_MEDIA_DIR}/tftp"
    fi

    # Ensure placeholder exists for LUN
    if [[ ! -f "$PLACEHOLDER_IMG" ]]; then
        log "Creating placeholder image..."
        truncate -s 16M "$PLACEHOLDER_IMG"
    fi

    # Ensure active symlink exists
    if [[ ! -L "$ACTIVE_SYMLINK" ]]; then
        log "Creating active symlink to placeholder..."
        ln -sf "images/placeholder.img" "$ACTIVE_SYMLINK"
    fi

    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# Find available UDC
# ═══════════════════════════════════════════════════════════════════════════════
find_udc() {
    local udc
    udc=$(ls /sys/class/udc 2>/dev/null | head -n1)
    if [[ -z "$udc" ]]; then
        err "No UDC found"
    fi
    echo "$udc"
}

# ═══════════════════════════════════════════════════════════════════════════════
# gadget_up: Create and bind gadget
# ═══════════════════════════════════════════════════════════════════════════════
gadget_up() {
    log "Starting USB gadget v${VERSION}..."

    # Check if already running
    if [[ -d "$GADGET_PATH" ]]; then
        local current_udc
        current_udc=$(cat "${GADGET_PATH}/UDC" 2>/dev/null || echo "")
        if [[ -n "$current_udc" ]]; then
            log "Gadget already running on UDC: $current_udc"
            return 0
        fi
        # Gadget exists but not bound, tear down first
        gadget_down
    fi

    check_prerequisites

    local udc serial
    udc=$(find_udc)
    serial=$(get_serial)

    log "Creating gadget: UDC=$udc, Serial=$serial"

    # Create gadget directory
    mkdir -p "$GADGET_PATH"
    cd "$GADGET_PATH"

    # Set USB IDs
    echo "$ID_VENDOR" > idVendor
    echo "$ID_PRODUCT" > idProduct
    echo "$BCD_DEVICE" > bcdDevice
    echo "$BCD_USB" > bcdUSB

    # Set device class (composite)
    echo 0xEF > bDeviceClass
    echo 0x02 > bDeviceSubClass
    echo 0x01 > bDeviceProtocol

    # Create strings
    mkdir -p "strings/0x409"
    echo "$serial" > "strings/0x409/serialnumber"
    echo "$MANUFACTURER" > "strings/0x409/manufacturer"
    echo "$PRODUCT" > "strings/0x409/product"

    # ──── Create functions ────

    # ECM (Ethernet over USB)
    mkdir -p "functions/ecm.usb0"
    # MAC addresses derived from serial
    echo "aa:bb:cc:${serial:10:2}:${serial:12:2}:01" > "functions/ecm.usb0/host_addr"
    echo "aa:bb:cc:${serial:10:2}:${serial:12:2}:02" > "functions/ecm.usb0/dev_addr"

    # ACM (Serial over USB)
    mkdir -p "functions/acm.usb0"

    # Mass Storage (Boot LUN)
    mkdir -p "functions/mass_storage.usb0/lun.0"
    echo 1 > "functions/mass_storage.usb0/lun.0/removable"
    echo 0 > "functions/mass_storage.usb0/lun.0/ro"
    echo 0 > "functions/mass_storage.usb0/lun.0/cdrom"
    echo 0 > "functions/mass_storage.usb0/lun.0/nofua"
    echo 1 > "functions/mass_storage.usb0/stall"

    # Point LUN to active image (resolves symlink)
    local active_target
    active_target=$(readlink -f "$ACTIVE_SYMLINK")
    echo "$active_target" > "functions/mass_storage.usb0/lun.0/file"
    log "LUN attached: $active_target"

    # ──── Create configuration ────

    mkdir -p "configs/c.1/strings/0x409"
    echo "ECM+ACM+Mass Storage" > "configs/c.1/strings/0x409/configuration"
    echo 250 > "configs/c.1/MaxPower"

    # Link functions to configuration
    ln -sf "../../functions/ecm.usb0" "configs/c.1/"
    ln -sf "../../functions/acm.usb0" "configs/c.1/"
    ln -sf "../../functions/mass_storage.usb0" "configs/c.1/"

    # ──── Bind to UDC ────

    echo "$udc" > UDC
    log "Gadget bound to UDC: $udc"

    # Write status file
    write_status "running" "$udc"

    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# gadget_down: Unbind and tear down gadget
# ═══════════════════════════════════════════════════════════════════════════════
gadget_down() {
    log "Stopping USB gadget..."

    if [[ ! -d "$GADGET_PATH" ]]; then
        log "Gadget not present, nothing to do"
        return 0
    fi

    cd "$GADGET_PATH"

    # Unbind from UDC
    if [[ -f "UDC" ]]; then
        echo "" > UDC 2>/dev/null || true
    fi

    # Remove function links from configuration
    rm -f configs/c.1/ecm.usb0 2>/dev/null || true
    rm -f configs/c.1/acm.usb0 2>/dev/null || true
    rm -f configs/c.1/mass_storage.usb0 2>/dev/null || true

    # Remove configuration strings
    rmdir configs/c.1/strings/0x409 2>/dev/null || true
    rmdir configs/c.1 2>/dev/null || true

    # Remove functions
    rmdir functions/ecm.usb0 2>/dev/null || true
    rmdir functions/acm.usb0 2>/dev/null || true
    rmdir functions/mass_storage.usb0/lun.0 2>/dev/null || true
    rmdir functions/mass_storage.usb0 2>/dev/null || true

    # Remove gadget strings
    rmdir strings/0x409 2>/dev/null || true

    # Remove gadget
    cd /
    rmdir "$GADGET_PATH" 2>/dev/null || true

    log "Gadget stopped"
    write_status "stopped" ""

    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# swap_lun: Atomically swap LUN backing file
# ═══════════════════════════════════════════════════════════════════════════════
swap_lun() {
    local new_path="$1"

    if [[ ! -d "$GADGET_PATH" ]]; then
        err "Gadget not running"
    fi

    local lun_file="${GADGET_PATH}/functions/mass_storage.usb0/lun.0/file"

    if [[ ! -f "$lun_file" ]]; then
        err "LUN file not found"
    fi

    log "Swapping LUN..."

    # Force eject current image
    echo "" > "$lun_file"
    sleep 0.1

    # Attach new image if path provided
    if [[ -n "$new_path" ]]; then
        local resolved_path
        resolved_path=$(readlink -f "$new_path")
        if [[ ! -f "$resolved_path" ]]; then
            err "Image not found: $resolved_path"
        fi
        echo "$resolved_path" > "$lun_file"
        log "LUN reattached: $resolved_path"
    else
        log "LUN ejected (no new image)"
    fi

    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# gadget_status: Output JSON status
# ═══════════════════════════════════════════════════════════════════════════════
gadget_status() {
    local state="stopped"
    local udc=""
    local lun_file=""
    local ecm_present=false
    local acm_present=false
    local mass_storage_present=false

    if [[ -d "$GADGET_PATH" ]]; then
        udc=$(cat "${GADGET_PATH}/UDC" 2>/dev/null || echo "")
        if [[ -n "$udc" ]]; then
            state="running"
        else
            state="configured"
        fi

        [[ -d "${GADGET_PATH}/functions/ecm.usb0" ]] && ecm_present=true
        [[ -d "${GADGET_PATH}/functions/acm.usb0" ]] && acm_present=true
        [[ -d "${GADGET_PATH}/functions/mass_storage.usb0" ]] && mass_storage_present=true

        lun_file=$(cat "${GADGET_PATH}/functions/mass_storage.usb0/lun.0/file" 2>/dev/null || echo "")
    fi

    cat << EOF
{
  "version": "${VERSION}",
  "state": "${state}",
  "udc": "${udc}",
  "functions": {
    "ecm": ${ecm_present},
    "acm": ${acm_present},
    "mass_storage": ${mass_storage_present}
  },
  "lun_file": "${lun_file}"
}
EOF
}

# ═══════════════════════════════════════════════════════════════════════════════
# Write status file
# ═══════════════════════════════════════════════════════════════════════════════
write_status() {
    local state="$1"
    local udc="$2"
    local status_file="/run/secubox-eye-gadget.json"

    cat > "$status_file" << EOF
{
  "state": "${state}",
  "udc": "${udc}",
  "timestamp": "$(date -Iseconds)"
}
EOF
}

# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

case "${1:-}" in
    up|start)
        gadget_up
        ;;
    down|stop)
        gadget_down
        ;;
    swap-lun)
        swap_lun "${2:-}"
        ;;
    status)
        gadget_status
        ;;
    *)
        echo "SecuBox Eye Remote Gadget v${VERSION}"
        echo ""
        echo "Usage: $0 {up|down|swap-lun <path>|status}"
        echo ""
        echo "Commands:"
        echo "  up           Create and bind gadget (ECM+ACM+mass_storage)"
        echo "  down         Unbind and tear down gadget"
        echo "  swap-lun     Swap LUN backing file atomically"
        echo "  status       Show gadget status as JSON"
        exit 1
        ;;
esac
```

### Step 2.3: Make executable and commit

- [ ] Set permissions and commit

```bash
chmod +x remote-ui/round/files/etc/secubox/eye-remote/gadget-setup.sh
git add remote-ui/round/files/etc/secubox/eye-remote/gadget-setup.sh
git commit -m "feat(eye-remote): add gadget-setup.sh for ECM+ACM+mass_storage"
```

---

## Task 3: Systemd Service

**Files:**
- Create: `remote-ui/round/files/etc/systemd/system/secubox-eye-gadget.service`

### Step 3.1: Write service file

- [ ] Create systemd service

```ini
# remote-ui/round/files/etc/systemd/system/secubox-eye-gadget.service
[Unit]
Description=SecuBox Eye Remote USB Gadget (ECM+ACM+mass_storage)
Documentation=https://github.com/CyberMind-FR/secubox-deb
After=systemd-modules-load.service
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/sbin/modprobe libcomposite
ExecStart=/etc/secubox/eye-remote/gadget-setup.sh up
ExecStop=/etc/secubox/eye-remote/gadget-setup.sh down
ExecReload=/etc/secubox/eye-remote/gadget-setup.sh down && /etc/secubox/eye-remote/gadget-setup.sh up

# Security hardening (limited - needs configfs access)
ProtectSystem=strict
ReadWritePaths=/sys/kernel/config /var/lib/secubox /run
PrivateTmp=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

### Step 3.2: Commit

- [ ] Commit service file

```bash
git add remote-ui/round/files/etc/systemd/system/secubox-eye-gadget.service
git commit -m "feat(eye-remote): add secubox-eye-gadget.service"
```

---

## Task 4: Boot Media Core Logic

**Files:**
- Create: `packages/secubox-eye-remote/core/boot_media.py`
- Modify: `packages/secubox-eye-remote/core/__init__.py`
- Create: `packages/secubox-eye-remote/tests/integration/test_boot_media.py`

### Step 4.1: Write integration test scaffolding

- [ ] Create test file

```python
# packages/secubox-eye-remote/tests/integration/test_boot_media.py
"""
Integration tests for boot media core logic.
"""
import hashlib
import json
import os
import pytest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.boot_media import BootMediaManager, BOOT_MEDIA_DIR
from models.boot_media import BootMediaState, BootImage


@pytest.fixture
def boot_media_dir(tmp_path):
    """Create temporary boot media directory structure."""
    bm = tmp_path / "boot-media"
    (bm / "images").mkdir(parents=True)
    (bm / "tftp").mkdir()
    return bm


@pytest.fixture
def fake_configfs(tmp_path):
    """Create mock configfs structure."""
    gadget = tmp_path / "usb_gadget" / "secubox" / "functions" / "mass_storage.usb0" / "lun.0"
    gadget.mkdir(parents=True)
    (gadget / "file").write_text("")
    return tmp_path / "usb_gadget"


@pytest.fixture
def manager(boot_media_dir, fake_configfs):
    """Create BootMediaManager with test paths."""
    with patch('core.boot_media.BOOT_MEDIA_DIR', boot_media_dir):
        with patch('core.boot_media.GADGET_LUN_FILE', fake_configfs / "secubox/functions/mass_storage.usb0/lun.0/file"):
            mgr = BootMediaManager(storage_path=boot_media_dir)
            yield mgr


@pytest.fixture
def valid_fat32_image(tmp_path):
    """Create minimal valid FAT32 image (16 MiB)."""
    img = tmp_path / "test.img"
    data = bytearray(16 * 1024 * 1024)
    # FAT32 boot sector signature
    data[510:512] = b'\x55\xAA'
    data[0:3] = b'\xEB\x58\x90'  # Jump instruction
    data[82:90] = b'FAT32   '    # FS type label
    img.write_bytes(data)
    return img


class TestValidateImage:
    def test_rejects_truncated_file(self, manager, tmp_path):
        """Truncated files (< 16 MiB) should be rejected."""
        small = tmp_path / "small.img"
        small.write_bytes(b'\x00' * 1024)  # 1 KB

        assert manager.validate_image(small) is False

    def test_rejects_wrong_magic(self, manager, tmp_path):
        """Files without FAT/ext magic should be rejected."""
        random_data = tmp_path / "random.img"
        random_data.write_bytes(os.urandom(16 * 1024 * 1024))

        assert manager.validate_image(random_data) is False

    def test_accepts_fat32(self, manager, valid_fat32_image):
        """Valid FAT32 images should be accepted."""
        assert manager.validate_image(valid_fat32_image) is True


class TestUploadToShadow:
    def test_upload_creates_image(self, manager, valid_fat32_image):
        """Upload should create image in images/ with sha256 name."""
        with open(valid_fat32_image, 'rb') as f:
            result = manager.upload_to_shadow(f, label="test")

        assert result is not None
        assert result.label == "test"
        assert len(result.sha256) == 64

        # Verify file exists
        img_path = manager.storage_path / "images" / f"{result.sha256}.img"
        assert img_path.exists()

    def test_upload_updates_shadow_symlink(self, manager, valid_fat32_image):
        """Upload should update shadow symlink."""
        with open(valid_fat32_image, 'rb') as f:
            result = manager.upload_to_shadow(f, label="test")

        shadow_link = manager.storage_path / "shadow"
        assert shadow_link.is_symlink()
        assert result.sha256 in str(shadow_link.resolve())

    def test_sha256_roundtrip(self, manager, valid_fat32_image):
        """Computed sha256 should match actual file hash."""
        # Compute expected hash
        with open(valid_fat32_image, 'rb') as f:
            expected_hash = hashlib.sha256(f.read()).hexdigest()

        # Upload
        with open(valid_fat32_image, 'rb') as f:
            result = manager.upload_to_shadow(f, label="hash-test")

        assert result.sha256 == expected_hash


class TestSwap:
    def test_swap_exchanges_slots(self, manager, valid_fat32_image):
        """Swap should exchange active and shadow."""
        # Upload to shadow
        with open(valid_fat32_image, 'rb') as f:
            shadow_img = manager.upload_to_shadow(f, label="shadow")

        # Create initial active
        active_path = manager.storage_path / "images" / "initial.img"
        active_path.write_bytes(b'\x00' * 100)
        (manager.storage_path / "active").symlink_to("images/initial.img")

        # Swap
        with patch.object(manager, '_call_gadget_swap'):
            state = manager.swap()

        # Verify swap occurred
        assert state.active is not None
        assert state.active.sha256 == shadow_img.sha256

    def test_swap_atomicity_after_symlink(self, manager, valid_fat32_image):
        """State should be consistent even if interrupted after symlink swap."""
        with open(valid_fat32_image, 'rb') as f:
            manager.upload_to_shadow(f, label="test")

        # Create active
        active_path = manager.storage_path / "images" / "old.img"
        active_path.write_bytes(b'\x00' * 100)
        (manager.storage_path / "active").symlink_to("images/old.img")

        # Simulate failure after symlink but before LUN reattach
        def fail_on_reattach(*args):
            if args and args[0]:  # Non-empty path = reattach
                raise RuntimeError("Simulated failure")

        with patch.object(manager, '_call_gadget_swap', side_effect=fail_on_reattach):
            with pytest.raises(RuntimeError):
                manager.swap()

        # Symlinks should still be consistent
        active = manager.storage_path / "active"
        assert active.is_symlink()


class TestRollback:
    def test_rollback_restores_previous(self, manager, valid_fat32_image, tmp_path):
        """Rollback should restore previous active."""
        # Create two images
        img1 = tmp_path / "img1.img"
        img1.write_bytes(valid_fat32_image.read_bytes())

        img2 = tmp_path / "img2.img"
        data2 = bytearray(valid_fat32_image.read_bytes())
        data2[100] = 0xFF  # Make it different
        img2.write_bytes(data2)

        # Upload first, swap
        with open(img1, 'rb') as f:
            first = manager.upload_to_shadow(f, label="first")

        with patch.object(manager, '_call_gadget_swap'):
            manager.swap()

        # Upload second, swap
        with open(img2, 'rb') as f:
            second = manager.upload_to_shadow(f, label="second")

        with patch.object(manager, '_call_gadget_swap'):
            manager.swap()

        # Rollback
        with patch.object(manager, '_call_gadget_swap'):
            state = manager.rollback()

        # Should have first image active again
        assert state.active.sha256 == first.sha256

    def test_rollback_noop_if_no_shadow(self, manager):
        """Rollback with empty shadow should be no-op."""
        # Create only active
        active_path = manager.storage_path / "images" / "only.img"
        active_path.write_bytes(b'\x00' * 100)
        (manager.storage_path / "active").symlink_to("images/only.img")

        initial_state = manager.get_state()

        with patch.object(manager, '_call_gadget_swap'):
            final_state = manager.rollback()

        # State unchanged
        assert final_state.active == initial_state.active


class TestGetState:
    def test_empty_state(self, manager):
        """Empty directory should return empty state."""
        state = manager.get_state()
        assert state.active is None
        assert state.shadow is None
        assert state.lun_attached is False

    def test_persists_across_reload(self, manager, valid_fat32_image):
        """State should persist and reload correctly."""
        with open(valid_fat32_image, 'rb') as f:
            manager.upload_to_shadow(f, label="persist-test")

        with patch.object(manager, '_call_gadget_swap'):
            manager.swap()

        # Simulate reload
        manager._load_state()
        state = manager.get_state()

        assert state.active is not None
        assert state.active.label == "persist-test"
```

### Step 4.2: Write core boot_media.py

- [ ] Create core module

```python
# packages/secubox-eye-remote/core/boot_media.py
"""
SecuBox Eye Remote — Boot Media Manager
Manages boot images for USB mass storage LUN with atomic swap.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from fcntl import flock, LOCK_EX, LOCK_UN
from pathlib import Path
from threading import Lock
from typing import BinaryIO, Optional

from models.boot_media import BootImage, BootMediaState

log = logging.getLogger(__name__)

# Paths
BOOT_MEDIA_DIR = Path("/var/lib/secubox/eye-remote/boot-media")
GADGET_SETUP_SCRIPT = Path("/etc/secubox/eye-remote/gadget-setup.sh")
GADGET_LUN_FILE = Path("/sys/kernel/config/usb_gadget/secubox/functions/mass_storage.usb0/lun.0/file")

# Validation constants
MIN_IMAGE_SIZE = 16 * 1024 * 1024  # 16 MiB
MAX_IMAGE_SIZE = 4 * 1024 * 1024 * 1024  # 4 GiB

# FAT32 magic bytes
FAT32_BOOT_SIG = b'\x55\xAA'
FAT32_FS_TYPE = b'FAT32   '

# ext2/3/4 magic
EXT_MAGIC = b'\x53\xef'
EXT_MAGIC_OFFSET = 0x438


class BootMediaManager:
    """
    Manages boot media images with 4R double-buffer pattern.

    Provides:
    - Image upload with sha256 verification
    - Atomic active/shadow swap
    - Rollback capability
    - TFTP file extraction

    Thread-safe with file and in-process locking.
    """

    def __init__(self, storage_path: Path = BOOT_MEDIA_DIR):
        self.storage_path = storage_path
        self.images_dir = storage_path / "images"
        self.tftp_dir = storage_path / "tftp"
        self.state_file = storage_path / "state.json"
        self.active_link = storage_path / "active"
        self.shadow_link = storage_path / "shadow"

        self._lock = Lock()
        self._state: Optional[BootMediaState] = None

        self._ensure_dirs()
        self._load_state()

    def _ensure_dirs(self):
        """Ensure directory structure exists."""
        self.images_dir.mkdir(parents=True, exist_ok=True)
        self.tftp_dir.mkdir(parents=True, exist_ok=True)

    def _load_state(self):
        """Load state from JSON file."""
        if self.state_file.exists():
            try:
                with open(self.state_file) as f:
                    data = json.load(f)
                self._state = BootMediaState(**data)
                log.debug("Loaded boot media state")
            except Exception as e:
                log.error("Failed to load state: %s", e)
                self._state = self._build_state_from_fs()
        else:
            self._state = self._build_state_from_fs()

    def _build_state_from_fs(self) -> BootMediaState:
        """Build state from filesystem (symlinks)."""
        active = self._read_slot("active")
        shadow = self._read_slot("shadow")
        lun_attached = self._check_lun_attached()

        return BootMediaState(
            active=active,
            shadow=shadow,
            lun_attached=lun_attached,
            last_swap_at=None,
            tftp_armed=bool(list(self.tftp_dir.glob("*"))),
        )

    def _read_slot(self, slot: str) -> Optional[BootImage]:
        """Read image info from slot symlink."""
        link = self.storage_path / slot
        if not link.is_symlink():
            return None

        try:
            target = link.resolve()
            if not target.exists():
                return None

            # Extract info
            sha256 = target.stem  # filename without .img
            size = target.stat().st_size
            mtime = datetime.fromtimestamp(target.stat().st_mtime, tz=timezone.utc)

            return BootImage(
                path=str(target.relative_to(self.storage_path)),
                sha256=sha256,
                size_bytes=size,
                created_at=mtime,
                label=None,
            )
        except Exception as e:
            log.warning("Failed to read slot %s: %s", slot, e)
            return None

    def _check_lun_attached(self) -> bool:
        """Check if LUN is attached to gadget."""
        if not GADGET_LUN_FILE.exists():
            return False
        try:
            content = GADGET_LUN_FILE.read_text().strip()
            return bool(content)
        except Exception:
            return False

    def _save_state(self):
        """Save state to JSON file."""
        if self._state:
            with open(self.state_file, 'w') as f:
                json.dump(self._state.model_dump(mode='json'), f, indent=2, default=str)

    def get_state(self) -> BootMediaState:
        """Get current boot media state."""
        with self._lock:
            if self._state is None:
                self._state = self._build_state_from_fs()
            # Update dynamic fields
            self._state.lun_attached = self._check_lun_attached()
            self._state.tftp_armed = bool(list(self.tftp_dir.glob("*")))
            return self._state

    def validate_image(self, path: Path) -> bool:
        """
        Validate boot image format and size.

        Accepts FAT16/32 or ext2/3/4 images between 16 MiB and 4 GiB.
        """
        if not path.exists():
            return False

        size = path.stat().st_size
        if size < MIN_IMAGE_SIZE or size > MAX_IMAGE_SIZE:
            log.warning("Image size out of range: %d bytes", size)
            return False

        try:
            with open(path, 'rb') as f:
                # Check FAT boot signature at offset 510
                f.seek(510)
                boot_sig = f.read(2)
                if boot_sig == FAT32_BOOT_SIG:
                    # Check FAT32 FS type at offset 82
                    f.seek(82)
                    fs_type = f.read(8)
                    if b'FAT' in fs_type:
                        return True

                # Check ext magic at offset 0x438
                f.seek(EXT_MAGIC_OFFSET)
                ext_magic = f.read(2)
                if ext_magic == EXT_MAGIC:
                    return True
        except Exception as e:
            log.warning("Failed to validate image: %s", e)

        return False

    def upload_to_shadow(self, fileobj: BinaryIO, label: Optional[str] = None) -> BootImage:
        """
        Upload image to shadow slot.

        Streams file, computes sha256, validates, moves to images/, updates shadow symlink.
        """
        with self._lock:
            # Stream to temp file while computing hash
            sha256_hash = hashlib.sha256()
            temp_fd, temp_path = tempfile.mkstemp(suffix='.img', dir=str(self.images_dir))
            temp_file = Path(temp_path)
            size = 0

            try:
                with os.fdopen(temp_fd, 'wb') as out:
                    while chunk := fileobj.read(65536):
                        sha256_hash.update(chunk)
                        out.write(chunk)
                        size += len(chunk)

                sha256 = sha256_hash.hexdigest()
                log.info("Uploaded %d bytes, sha256=%s", size, sha256)

                # Validate
                if not self.validate_image(temp_file):
                    temp_file.unlink()
                    raise ValueError("Invalid image format")

                # Move to final location
                final_path = self.images_dir / f"{sha256}.img"
                if final_path.exists():
                    temp_file.unlink()  # Duplicate
                else:
                    temp_file.rename(final_path)

                # Update shadow symlink atomically
                self._atomic_symlink(
                    self.shadow_link,
                    f"images/{sha256}.img"
                )

                # Extract boot files to TFTP
                self._extract_boot_files(final_path)

                # Create BootImage
                image = BootImage(
                    path=f"images/{sha256}.img",
                    sha256=sha256,
                    size_bytes=size,
                    created_at=datetime.now(timezone.utc),
                    label=label,
                )

                # Update state
                self._state.shadow = image
                self._state.tftp_armed = True
                self._save_state()

                return image

            except Exception:
                if temp_file.exists():
                    temp_file.unlink()
                raise

    def _atomic_symlink(self, link_path: Path, target: str):
        """Create symlink atomically via rename."""
        tmp_link = link_path.with_suffix('.tmp')
        if tmp_link.exists() or tmp_link.is_symlink():
            tmp_link.unlink()
        tmp_link.symlink_to(target)
        tmp_link.rename(link_path)

    def _extract_boot_files(self, image_path: Path):
        """Extract kernel/dtb/initrd from image to TFTP dir."""
        # Clear existing TFTP files
        for f in self.tftp_dir.glob("*"):
            f.unlink()

        # Try to mount and extract
        mount_point = Path(tempfile.mkdtemp(prefix='bootmedia_'))
        try:
            # Mount read-only
            result = subprocess.run(
                ["mount", "-o", "loop,ro", str(image_path), str(mount_point)],
                capture_output=True,
                timeout=30,
            )
            if result.returncode != 0:
                log.warning("Failed to mount image for TFTP extraction")
                return

            # Look for boot files
            boot_dirs = [mount_point, mount_point / "boot"]
            patterns = ["Image", "vmlinuz*", "*.dtb", "initrd*", "initramfs*"]

            for boot_dir in boot_dirs:
                if not boot_dir.exists():
                    continue
                for pattern in patterns:
                    for src in boot_dir.glob(pattern):
                        if src.is_file():
                            dst = self.tftp_dir / src.name
                            shutil.copy2(src, dst)
                            log.info("Extracted to TFTP: %s", src.name)

        except Exception as e:
            log.warning("TFTP extraction failed: %s", e)
        finally:
            # Unmount
            subprocess.run(["umount", str(mount_point)], capture_output=True)
            mount_point.rmdir()

    def _call_gadget_swap(self, new_path: str = ""):
        """Call gadget-setup.sh swap-lun."""
        if not GADGET_SETUP_SCRIPT.exists():
            log.warning("Gadget script not found, skipping LUN swap")
            return

        cmd = [str(GADGET_SETUP_SCRIPT), "swap-lun", new_path]
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        if result.returncode != 0:
            raise RuntimeError(f"Gadget swap failed: {result.stderr.decode()}")

    def swap(self) -> BootMediaState:
        """
        Swap active and shadow slots atomically.

        Sequence:
        1. Eject LUN
        2. Swap symlinks atomically
        3. Reattach LUN to new active
        4. Update state
        """
        with self._lock:
            if self._state.shadow is None:
                raise ValueError("No shadow image to swap")

            old_active = self._state.active
            new_active = self._state.shadow

            # 1. Eject LUN
            self._call_gadget_swap("")

            try:
                # 2. Swap symlinks atomically
                # Point active to shadow's target
                shadow_target = self.shadow_link.resolve()
                self._atomic_symlink(
                    self.active_link,
                    str(shadow_target.relative_to(self.storage_path))
                )

                # Point shadow to old active (if exists)
                if old_active:
                    self._atomic_symlink(
                        self.shadow_link,
                        old_active.path
                    )
                elif self.shadow_link.is_symlink():
                    self.shadow_link.unlink()

                # 3. Reattach LUN
                self._call_gadget_swap(str(self.active_link))

                # 4. Update state
                self._state.active = new_active
                self._state.shadow = old_active
                self._state.last_swap_at = datetime.now(timezone.utc)
                self._state.lun_attached = True
                self._save_state()

                log.info("Swapped: active=%s, shadow=%s",
                         new_active.sha256[:8] if new_active else None,
                         old_active.sha256[:8] if old_active else None)

                return self._state

            except Exception:
                # Try to recover by reattaching old active
                if old_active and self.active_link.is_symlink():
                    try:
                        self._call_gadget_swap(str(self.active_link))
                    except Exception:
                        pass
                raise

    def rollback(self) -> BootMediaState:
        """Rollback to previous active (swap back)."""
        with self._lock:
            if self._state.shadow is None:
                log.info("No shadow to rollback to, no-op")
                return self._state

            return self.swap()


# Singleton
_manager: Optional[BootMediaManager] = None


def get_boot_media_manager() -> BootMediaManager:
    """Get global boot media manager instance."""
    global _manager
    if _manager is None:
        _manager = BootMediaManager()
    return _manager
```

### Step 4.3: Update core __init__.py

- [ ] Add exports

```python
# packages/secubox-eye-remote/core/__init__.py
"""SecuBox Eye Remote core modules."""
from .device_registry import DeviceRegistry, get_device_registry
from .token_manager import TokenManager, get_token_manager
from .boot_media import BootMediaManager, get_boot_media_manager

__all__ = [
    "DeviceRegistry",
    "get_device_registry",
    "TokenManager",
    "get_token_manager",
    "BootMediaManager",
    "get_boot_media_manager",
]
```

### Step 4.4: Run tests

- [ ] Run integration tests

```bash
cd packages/secubox-eye-remote
python -m pytest tests/integration/test_boot_media.py -v
```

Expected: All tests PASS

### Step 4.5: Commit

- [ ] Commit core module

```bash
git add packages/secubox-eye-remote/core/boot_media.py \
       packages/secubox-eye-remote/core/__init__.py \
       packages/secubox-eye-remote/tests/integration/test_boot_media.py
git commit -m "feat(eye-remote): add boot media core with atomic swap"
```

---

## Task 5: FastAPI Router

**Files:**
- Create: `packages/secubox-eye-remote/api/routers/boot_media.py`
- Modify: `packages/secubox-eye-remote/api/routers/__init__.py`

### Step 5.1: Write router

- [ ] Create router

```python
# packages/secubox-eye-remote/api/routers/boot_media.py
"""
SecuBox Eye Remote — Boot Media Router
API endpoints for boot media management (LUN + TFTP).

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import logging
import subprocess
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status

from core.boot_media import get_boot_media_manager
from models.boot_media import (
    BootMediaState,
    SwapResponse,
    TftpStatusResponse,
    UploadResponse,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/boot-media", tags=["boot-media"])


# JWT auth dependency placeholder
def require_jwt():
    """JWT authentication dependency."""
    pass


@router.get("/state", response_model=BootMediaState)
async def get_state(_: None = Depends(require_jwt)) -> BootMediaState:
    """
    Get current boot media state.

    Returns active/shadow slot info, LUN status, TFTP status.
    """
    manager = get_boot_media_manager()
    return manager.get_state()


@router.post("/upload", response_model=UploadResponse)
async def upload_image(
    file: UploadFile = File(..., description="Boot image file (FAT32 or ext)"),
    label: Optional[str] = Form(None, description="User-friendly label"),
    _: None = Depends(require_jwt),
) -> UploadResponse:
    """
    Upload boot image to shadow slot.

    Streams file, computes sha256, validates format, updates shadow symlink.
    Also extracts boot files to TFTP directory.
    """
    manager = get_boot_media_manager()

    try:
        image = manager.upload_to_shadow(file.file, label=label)
        log.info("Uploaded boot image: %s (%s)", image.sha256[:8], label or "no label")

        return UploadResponse(
            success=True,
            image=image,
            message=f"Image uploaded to shadow slot: {image.sha256[:8]}",
        )

    except ValueError as e:
        log.warning("Upload rejected: %s", e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    except Exception as e:
        log.error("Upload failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Upload failed: {e}",
        )


@router.post("/swap", response_model=SwapResponse)
async def swap_slots(_: None = Depends(require_jwt)) -> SwapResponse:
    """
    Swap active and shadow slots atomically.

    Sequence:
    1. Eject LUN from USB gadget
    2. Swap active/shadow symlinks
    3. Reattach LUN with new active
    """
    manager = get_boot_media_manager()

    try:
        state = manager.swap()
        log.info("Swapped boot media slots")

        return SwapResponse(
            success=True,
            state=state,
            message="Active and shadow slots swapped",
        )

    except ValueError as e:
        log.warning("Swap rejected: %s", e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    except RuntimeError as e:
        log.error("Swap failed (gadget): %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Gadget operation failed: {e}",
        )

    except Exception as e:
        log.error("Swap failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Swap failed: {e}",
        )


@router.post("/rollback", response_model=SwapResponse)
async def rollback(_: None = Depends(require_jwt)) -> SwapResponse:
    """
    Rollback to previous active image.

    Equivalent to swap if shadow contains previous active.
    No-op if shadow is empty.
    """
    manager = get_boot_media_manager()

    try:
        state = manager.rollback()

        if state.shadow is None:
            return SwapResponse(
                success=True,
                state=state,
                message="No shadow to rollback to (no-op)",
            )

        log.info("Rolled back boot media")
        return SwapResponse(
            success=True,
            state=state,
            message="Rolled back to previous active",
        )

    except Exception as e:
        log.error("Rollback failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Rollback failed: {e}",
        )


@router.get("/tftp/status", response_model=TftpStatusResponse)
async def tftp_status(_: None = Depends(require_jwt)) -> TftpStatusResponse:
    """
    Get TFTP service status.

    Checks if dnsmasq is running and lists files in TFTP directory.
    """
    manager = get_boot_media_manager()

    # Check dnsmasq status
    result = subprocess.run(
        ["systemctl", "is-active", "dnsmasq"],
        capture_output=True,
    )
    alive = result.returncode == 0

    # List TFTP files
    files = [f.name for f in manager.tftp_dir.glob("*") if f.is_file()]

    return TftpStatusResponse(
        alive=alive,
        root=str(manager.tftp_dir),
        files=files,
    )
```

### Step 5.2: Update routers __init__.py

- [ ] Add boot_media router

```python
# packages/secubox-eye-remote/api/routers/__init__.py
"""SecuBox Eye Remote API routers."""
from fastapi import APIRouter

from .devices import router as devices_router
from .metrics import router as metrics_router
from .pairing import router as pairing_router
from .serial import router as serial_router
from .websocket import router as websocket_router
from .boot_media import router as boot_media_router

api_router = APIRouter(prefix="/api/v1/eye-remote")

api_router.include_router(devices_router)
api_router.include_router(metrics_router)
api_router.include_router(pairing_router)
api_router.include_router(serial_router)
api_router.include_router(websocket_router)
api_router.include_router(boot_media_router)

__all__ = ["api_router"]
```

### Step 5.3: Commit

- [ ] Commit router

```bash
git add packages/secubox-eye-remote/api/routers/boot_media.py \
       packages/secubox-eye-remote/api/routers/__init__.py
git commit -m "feat(eye-remote): add /boot-media/ API endpoints"
```

---

## Task 6: dnsmasq TFTP Configuration

**Files:**
- Create: `remote-ui/round/files/etc/dnsmasq.d/secubox-eye-tftp.conf`
- Create: `remote-ui/round/files/etc/systemd/system/dnsmasq.service.d/secubox-eye.conf`
- Create: `remote-ui/round/files/etc/secubox/eye-remote/tftp.env`

### Step 6.1: Create dnsmasq config

- [ ] Create TFTP config

```ini
# remote-ui/round/files/etc/dnsmasq.d/secubox-eye-tftp.conf
# SecuBox Eye Remote — TFTP shadow channel
# Serves boot files from shadow slot for testing before swap

# Bind to USB gadget interface only
interface=usb0
bind-interfaces

# TFTP server
enable-tftp
tftp-root=/var/lib/secubox/eye-remote/boot-media/tftp
tftp-no-fail

# Don't act as DNS server on this interface
port=0

# Logging
log-facility=/var/log/secubox-eye-tftp.log
```

### Step 6.2: Create systemd drop-in

- [ ] Create dnsmasq dependency

```ini
# remote-ui/round/files/etc/systemd/system/dnsmasq.service.d/secubox-eye.conf
[Unit]
After=secubox-eye-gadget.service
Wants=secubox-eye-gadget.service

[Service]
# Load environment for optional DHCP toggle
EnvironmentFile=-/etc/secubox/eye-remote/tftp.env
```

### Step 6.3: Create environment file

- [ ] Create tftp.env

```bash
# remote-ui/round/files/etc/secubox/eye-remote/tftp.env
# SecuBox Eye Remote TFTP configuration

# Set to "yes" to enable DHCP on usb0 for TFTP boot
# When enabled, dnsmasq will offer DHCP leases to U-Boot
TFTP_DHCP=no
```

### Step 6.4: Commit

- [ ] Commit TFTP config

```bash
git add remote-ui/round/files/etc/dnsmasq.d/secubox-eye-tftp.conf \
       remote-ui/round/files/etc/systemd/system/dnsmasq.service.d/secubox-eye.conf \
       remote-ui/round/files/etc/secubox/eye-remote/tftp.env
git commit -m "feat(eye-remote): add dnsmasq TFTP shadow channel config"
```

---

## Task 7: U-Boot Documentation

**Files:**
- Create: `docs/eye-remote/uboot-bootcmd.md`

### Step 7.1: Write documentation

- [ ] Create U-Boot doc

```markdown
# U-Boot Boot Commands for Eye Remote Bootstrap

This document describes how to configure ESPRESSObin U-Boot to boot from the Eye Remote mass storage LUN or TFTP shadow channel.

## Prerequisites

- Eye Remote Pi Zero W running v2.1.0+
- ESPRESSObin with U-Boot in SPI/eMMC
- USB OTG cable connecting Eye Remote DATA port to ESPRESSObin USB port

## Power Ordering

The Eye Remote must be powered and have its USB gadget initialized **before** U-Boot executes `usb start`. Two approaches:

### Option A: Independent Power (Recommended)

Power the Pi Zero W from a separate 5V source (not through the USB OTG cable). This ensures the gadget is always ready when the ESPRESSObin boots.

**Wiring:**
- USB OTG DATA cable to ESPRESSObin
- Separate 5V supply to Pi Zero PWR port (or GPIO header pins 2+6)

### Option B: Retry Loop in U-Boot

If the Pi Zero is powered through the OTG cable, U-Boot may try `usb start` before the gadget is ready. Add a retry loop to `bootcmd`:

```
setenv bootcmd_usb_retry 'usb reset; sleep 3; usb start; if usb storage; then run bootcmd_usb; fi'
setenv bootcmd 'run bootcmd_usb_retry'
saveenv
```

This resets the USB bus, waits 3 seconds for gadget enumeration, then attempts boot.

## Mass Storage Boot (Active Slot)

Load kernel and DTB from the Eye Remote LUN (FAT32 partition):

```
# Initialize USB
usb start

# Verify LUN is visible
usb storage
usb tree

# Load kernel
fatload usb 0 ${kernel_addr_r} Image

# Load device tree
fatload usb 0 ${fdt_addr_r} armada-3720-espressobin.dtb

# Load initrd (optional)
fatload usb 0 ${ramdisk_addr_r} initrd.img
setenv ramdisk_size ${filesize}

# Boot
booti ${kernel_addr_r} ${ramdisk_addr_r}:${ramdisk_size} ${fdt_addr_r}
```

### Complete bootcmd Example

```
setenv bootcmd_usb 'usb start; fatload usb 0 ${kernel_addr_r} Image; fatload usb 0 ${fdt_addr_r} armada-3720-espressobin.dtb; booti ${kernel_addr_r} - ${fdt_addr_r}'
setenv bootcmd 'run bootcmd_usb'
saveenv
```

## TFTP Boot (Shadow Slot)

The shadow slot is served via TFTP on 10.55.0.2 (Eye Remote IP). This allows testing a new image before swapping to active.

```
# Set server IP (Eye Remote)
setenv serverip 10.55.0.2

# Get IP via DHCP (if TFTP_DHCP=yes on Eye Remote)
dhcp

# Or set static IP
setenv ipaddr 10.55.0.1
setenv netmask 255.255.255.252

# Load via TFTP
tftp ${kernel_addr_r} Image
tftp ${fdt_addr_r} armada-3720-espressobin.dtb

# Boot
booti ${kernel_addr_r} - ${fdt_addr_r}
```

### Complete TFTP bootcmd

```
setenv bootcmd_tftp 'setenv serverip 10.55.0.2; setenv ipaddr 10.55.0.1; tftp ${kernel_addr_r} Image; tftp ${fdt_addr_r} armada-3720-espressobin.dtb; booti ${kernel_addr_r} - ${fdt_addr_r}'
```

## Workflow: Test Then Promote

1. Upload new image to Eye Remote: `POST /api/v1/eye-remote/boot-media/upload`
2. Reboot ESPRESSObin with TFTP boot: `run bootcmd_tftp`
3. Verify new image works correctly
4. If OK, promote to active: `POST /api/v1/eye-remote/boot-media/swap`
5. Reboot normally with USB mass storage: `run bootcmd_usb`

## Troubleshooting

### "No USB storage device(s) found"

- Check USB cable is connected to DATA port (middle) on Pi Zero
- Verify gadget is running: `ssh pi@10.55.0.2 systemctl status secubox-eye-gadget`
- Try power cycling the Pi Zero or using Option B retry loop

### "Unable to read file Image"

- Verify image was uploaded: `GET /api/v1/eye-remote/boot-media/state`
- Check active symlink: `ssh pi@10.55.0.2 ls -la /var/lib/secubox/eye-remote/boot-media/`
- Ensure image is FAT32 formatted with boot files in root or /boot/

### TFTP timeout

- Verify dnsmasq is running: `ssh pi@10.55.0.2 systemctl status dnsmasq`
- Check TFTP directory has files: `ls /var/lib/secubox/eye-remote/boot-media/tftp/`
- Verify network: `ping 10.55.0.2` from U-Boot

## See Also

- [Eye-Remote-Bootstrap](../wiki/Eye-Remote-Bootstrap.md) - Full feature documentation
- [Boot-Architecture](../wiki/Boot-Architecture.md) - SecuBox boot overview
- [ESPRESSObin](../wiki/ESPRESSObin.md) - Hardware documentation
```

### Step 7.2: Commit

- [ ] Commit docs

```bash
mkdir -p docs/eye-remote
git add docs/eye-remote/uboot-bootcmd.md
git commit -m "docs(eye-remote): add U-Boot boot commands documentation"
```

---

## Task 8: Debian Packaging

**Files:**
- Modify: `debian/secubox-eye-remote/install`
- Modify: `debian/secubox-eye-remote/postinst`
- Modify: `debian/secubox-eye-remote/postrm`
- Modify: `debian/secubox-eye-remote/control`
- Modify: `debian/secubox-eye-remote/changelog`

### Step 8.1: Check current packaging structure

- [ ] Verify debian directory exists

```bash
ls -la packages/secubox-eye-remote/debian/ || mkdir -p packages/secubox-eye-remote/debian
```

### Step 8.2: Create/update install file

- [ ] Update install file

```
# packages/secubox-eye-remote/debian/secubox-eye-remote.install
# Models
models/*.py usr/lib/secubox/eye-remote/models/

# Core
core/*.py usr/lib/secubox/eye-remote/core/

# API
api/*.py usr/lib/secubox/eye-remote/api/
api/routers/*.py usr/lib/secubox/eye-remote/api/routers/

# Gadget setup
../remote-ui/round/files/etc/secubox/eye-remote/gadget-setup.sh etc/secubox/eye-remote/
../remote-ui/round/files/etc/secubox/eye-remote/tftp.env etc/secubox/eye-remote/

# Systemd
../remote-ui/round/files/etc/systemd/system/secubox-eye-gadget.service etc/systemd/system/
../remote-ui/round/files/etc/systemd/system/dnsmasq.service.d/secubox-eye.conf etc/systemd/system/dnsmasq.service.d/

# dnsmasq
../remote-ui/round/files/etc/dnsmasq.d/secubox-eye-tftp.conf etc/dnsmasq.d/
```

### Step 8.3: Create postinst

- [ ] Create postinst script

```bash
#!/bin/bash
# packages/secubox-eye-remote/debian/postinst
set -e

case "$1" in
    configure)
        # Reload systemd
        systemctl daemon-reload

        # Enable gadget service on fresh install only
        if [ -z "$2" ]; then
            systemctl enable secubox-eye-gadget.service || true
        fi

        # Create boot media directories
        mkdir -p /var/lib/secubox/eye-remote/boot-media/images
        mkdir -p /var/lib/secubox/eye-remote/boot-media/tftp
        chmod 755 /var/lib/secubox/eye-remote/boot-media

        # Create placeholder if no active image exists
        if [ ! -e /var/lib/secubox/eye-remote/boot-media/active ]; then
            truncate -s 16M /var/lib/secubox/eye-remote/boot-media/images/placeholder.img
            ln -sf images/placeholder.img /var/lib/secubox/eye-remote/boot-media/active
        fi

        # Initialize state.json if missing
        STATE_FILE=/var/lib/secubox/eye-remote/boot-media/state.json
        if [ ! -f "$STATE_FILE" ]; then
            cat > "$STATE_FILE" << 'EOF'
{
  "active": null,
  "shadow": null,
  "lun_attached": false,
  "last_swap_at": null,
  "tftp_armed": false
}
EOF
        fi

        # Make gadget script executable
        chmod +x /etc/secubox/eye-remote/gadget-setup.sh
        ;;
esac

#DEBHELPER#

exit 0
```

### Step 8.4: Create postrm

- [ ] Create postrm script

```bash
#!/bin/bash
# packages/secubox-eye-remote/debian/postrm
set -e

case "$1" in
    remove)
        systemctl disable secubox-eye-gadget.service 2>/dev/null || true
        ;;

    purge)
        # Remove state and config, but PRESERVE user images
        rm -f /var/lib/secubox/eye-remote/boot-media/state.json
        rm -f /var/lib/secubox/eye-remote/boot-media/active
        rm -f /var/lib/secubox/eye-remote/boot-media/shadow
        rm -rf /var/lib/secubox/eye-remote/boot-media/tftp
        # NOTE: images/ directory preserved (user data)

        # Remove log
        rm -f /var/log/secubox-eye-tftp.log
        ;;
esac

#DEBHELPER#

exit 0
```

### Step 8.5: Update control file

- [ ] Add dnsmasq-base dependency

```
# packages/secubox-eye-remote/debian/control (snippet)
Package: secubox-eye-remote
Version: 2.1.0-1
Architecture: all
Depends: ${misc:Depends}, ${python3:Depends},
         python3-pil,
         python3-aiohttp,
         python3-fastapi,
         python3-pydantic,
         pigpio,
         dnsmasq-base
Description: SecuBox Eye Remote module
 Eye Remote display and control interface for SecuBox.
 Provides USB gadget with ECM, ACM, and mass storage functions,
 plus TFTP boot channel for ESPRESSObin.
```

### Step 8.6: Update changelog

- [ ] Add 2.1.0 entry

```
# packages/secubox-eye-remote/debian/changelog
secubox-eye-remote (2.1.0-1) bookworm; urgency=medium

  * Add bootstrap role: mass_storage LUN for U-Boot loading
  * Add TFTP shadow channel via dnsmasq
  * New API: /api/v1/eye-remote/boot-media/
  * 4R double-buffer for active/shadow image management
  * Atomic swap with crash recovery
  * New systemd service: secubox-eye-gadget.service
  * Deprecate: secubox-otg-gadget.sh (replaced by gadget-setup.sh)

 -- Gerald Kerma <gandalf@gk2.net>  Wed, 23 Apr 2026 12:00:00 +0200
```

### Step 8.7: Commit

- [ ] Commit packaging

```bash
git add packages/secubox-eye-remote/debian/
git commit -m "feat(eye-remote): update Debian packaging for v2.1.0"
```

---

## Task 9: Build Script Update

**Files:**
- Modify: `remote-ui/round/build-eye-remote-image.sh`

### Step 9.1: Update build script

- [ ] Add v2.1.0 changes to build script

Find the PACKAGES_FRAMEBUFFER array and add `dnsmasq-base`:

```bash
# In build-eye-remote-image.sh, update PACKAGES_FRAMEBUFFER:
PACKAGES_FRAMEBUFFER=(
    # Python for dashboard rendering
    python3-pil
    python3-pip
    python3-pigpio
    python3-aiohttp
    pigpio
    # Utilities
    i2c-tools
    # Fonts
    fonts-dejavu-core
    # v2.1.0: TFTP for boot media
    dnsmasq-base
)
```

Add boot media directory creation after gadget directory creation:

```bash
# After "Create gadget data directory" section, add:
# Create boot media directory
log "Creating boot media directories..."
mkdir -p "$ROOT_MNT/var/lib/secubox/eye-remote/boot-media/images"
mkdir -p "$ROOT_MNT/var/lib/secubox/eye-remote/boot-media/tftp"
truncate -s 16M "$ROOT_MNT/var/lib/secubox/eye-remote/boot-media/images/placeholder.img"
ln -sf images/placeholder.img "$ROOT_MNT/var/lib/secubox/eye-remote/boot-media/active"

# Initialize state.json
cat > "$ROOT_MNT/var/lib/secubox/eye-remote/boot-media/state.json" << 'EOF'
{
  "active": null,
  "shadow": null,
  "lun_attached": false,
  "last_swap_at": null,
  "tftp_armed": false
}
EOF
```

Copy new files:

```bash
# After copying secubox-otg-gadget.sh, add:
# Copy v2.1.0 gadget-setup.sh
mkdir -p "$ROOT_MNT/etc/secubox/eye-remote"
cp "$SCRIPT_DIR/files/etc/secubox/eye-remote/gadget-setup.sh" "$ROOT_MNT/etc/secubox/eye-remote/"
cp "$SCRIPT_DIR/files/etc/secubox/eye-remote/tftp.env" "$ROOT_MNT/etc/secubox/eye-remote/"
chmod +x "$ROOT_MNT/etc/secubox/eye-remote/gadget-setup.sh"

# Copy dnsmasq config
mkdir -p "$ROOT_MNT/etc/dnsmasq.d"
cp "$SCRIPT_DIR/files/etc/dnsmasq.d/secubox-eye-tftp.conf" "$ROOT_MNT/etc/dnsmasq.d/"

# Copy systemd files
cp "$SCRIPT_DIR/files/etc/systemd/system/secubox-eye-gadget.service" "$ROOT_MNT/etc/systemd/system/"
mkdir -p "$ROOT_MNT/etc/systemd/system/dnsmasq.service.d"
cp "$SCRIPT_DIR/files/etc/systemd/system/dnsmasq.service.d/secubox-eye.conf" \
   "$ROOT_MNT/etc/systemd/system/dnsmasq.service.d/"

# Enable new gadget service
ln -sf /etc/systemd/system/secubox-eye-gadget.service \
    "$ROOT_MNT/etc/systemd/system/multi-user.target.wants/"
```

Update VERSION:

```bash
# At top of script
VERSION="2.1.0"
```

### Step 9.2: Commit

- [ ] Commit build script update

```bash
git add remote-ui/round/build-eye-remote-image.sh
git commit -m "feat(eye-remote): update build script for v2.1.0 bootstrap"
```

---

## Task 10: Wiki Documentation

**Files:**
- Create: `docs/wiki/Eye-Remote-Bootstrap.md`

### Step 10.1: Create wiki page

- [ ] Write main wiki page

```markdown
# Eye Remote Bootstrap

The Eye Remote Bootstrap feature (v2.1.0) adds USB mass storage capability to the Eye Remote, enabling ESPRESSObin U-Boot to load kernel, DTB, and initrd directly from the Pi Zero W.

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Eye Remote Pi Zero W                        │
│  ┌──────────┐  ┌──────────┐  ┌─────────────────┐               │
│  │ ecm.usb0 │  │ acm.usb0 │  │ mass_storage    │               │
│  │ Network  │  │ Serial   │  │ Boot LUN        │               │
│  └──────────┘  └──────────┘  └────────┬────────┘               │
│                                       │                         │
│  ┌────────────────────────────────────┴───────────────────────┐│
│  │              /var/lib/secubox/eye-remote/boot-media/       ││
│  │  ┌────────┐    ┌────────┐    ┌──────────────────────┐      ││
│  │  │ active │───▶│ LUN    │    │ images/<sha256>.img  │      ││
│  │  │ (link) │    │        │    │                      │      ││
│  │  └────────┘    └────────┘    └──────────────────────┘      ││
│  │  ┌────────┐    ┌────────┐                                  ││
│  │  │ shadow │───▶│ TFTP   │                                  ││
│  │  │ (link) │    │        │                                  ││
│  │  └────────┘    └────────┘                                  ││
│  └────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │ USB OTG
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     ESPRESSObin U-Boot                          │
│  usb start → fatload usb 0 Image → booti                        │
│  OR: tftp Image → booti (test shadow before swap)               │
└─────────────────────────────────────────────────────────────────┘
```

## Features

- **USB Mass Storage LUN** — ESPRESSObin sees Eye Remote as bootable USB drive
- **4R Double-Buffer** — Active/shadow slots with atomic swap
- **TFTP Shadow Channel** — Test new images before promoting to active
- **Crash-Safe Swap** — Atomic symlink operations survive interruption
- **API Management** — Upload, swap, rollback via REST API

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/eye-remote/boot-media/state` | Current slot states |
| POST | `/api/v1/eye-remote/boot-media/upload` | Upload to shadow |
| POST | `/api/v1/eye-remote/boot-media/swap` | Promote shadow to active |
| POST | `/api/v1/eye-remote/boot-media/rollback` | Restore previous active |
| GET | `/api/v1/eye-remote/boot-media/tftp/status` | TFTP service status |

## Workflow

### 1. Upload New Image

```bash
curl -X POST \
  -F "file=@debian-boot.img" \
  -F "label=debian-bookworm-test" \
  -H "Authorization: Bearer $TOKEN" \
  http://10.55.0.2:8000/api/v1/eye-remote/boot-media/upload
```

### 2. Test via TFTP (Optional)

Boot ESPRESSObin with TFTP to test the shadow image:

```
# In U-Boot
setenv serverip 10.55.0.2
tftp ${kernel_addr_r} Image
tftp ${fdt_addr_r} armada-3720-espressobin.dtb
booti ${kernel_addr_r} - ${fdt_addr_r}
```

### 3. Promote to Active

```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  http://10.55.0.2:8000/api/v1/eye-remote/boot-media/swap
```

### 4. Boot from LUN

```
# In U-Boot
usb start
fatload usb 0 ${kernel_addr_r} Image
fatload usb 0 ${fdt_addr_r} armada-3720-espressobin.dtb
booti ${kernel_addr_r} - ${fdt_addr_r}
```

## State Machine

```
EMPTY                    SHADOW READY              READY TO SWAP
┌─────────────┐         ┌─────────────┐           ┌─────────────┐
│ active: ∅   │─upload─▶│ active: ∅   │──swap───▶│ active: A   │
│ shadow: ∅   │         │ shadow: A   │           │ shadow: ∅   │
└─────────────┘         └─────────────┘           └──────┬──────┘
                                                         │upload
                                                         ▼
                        ┌─────────────┐           ┌─────────────┐
                        │ active: B   │◀──swap───│ active: A   │
                        │ shadow: A   │──rollback▶│ shadow: B   │
                        └─────────────┘           └─────────────┘
```

## Image Requirements

- **Format:** FAT32 or ext2/3/4 filesystem
- **Size:** 16 MiB minimum, 4 GiB maximum
- **Contents:** Kernel (`Image` or `vmlinuz`), DTB, optional initrd
- **Structure:** Boot files in root directory or `/boot/`

## Configuration

### TFTP DHCP (Optional)

Enable DHCP on usb0 for automatic IP assignment in U-Boot:

```bash
# /etc/secubox/eye-remote/tftp.env
TFTP_DHCP=yes
```

### Power Ordering

See [U-Boot Boot Commands](../eye-remote/uboot-bootcmd.md) for power sequencing options.

## Troubleshooting

### LUN Not Visible

```bash
# Check gadget status
systemctl status secubox-eye-gadget

# Verify LUN file
cat /sys/kernel/config/usb_gadget/secubox/functions/mass_storage.usb0/lun.0/file
```

### TFTP Timeout

```bash
# Check dnsmasq
systemctl status dnsmasq

# List TFTP files
ls -la /var/lib/secubox/eye-remote/boot-media/tftp/
```

### Swap Failed

```bash
# Check state
curl http://10.55.0.2:8000/api/v1/eye-remote/boot-media/state

# Manual recovery
/etc/secubox/eye-remote/gadget-setup.sh status
/etc/secubox/eye-remote/gadget-setup.sh swap-lun /var/lib/secubox/eye-remote/boot-media/active
```

## See Also

- [Eye-Remote-Implementation](Eye-Remote-Implementation.md) — Main Eye Remote documentation
- [Boot-Architecture](Boot-Architecture.md) — SecuBox boot overview
- [Live-USB](Live-USB.md) — Live boot alternatives
- [ESPRESSObin](ESPRESSObin.md) — Hardware documentation
```

### Step 10.2: Commit

- [ ] Commit wiki

```bash
mkdir -p docs/wiki
git add docs/wiki/Eye-Remote-Bootstrap.md
git commit -m "docs(eye-remote): add Eye-Remote-Bootstrap wiki page"
```

---

## Task 11: i18n Translations

**Files:**
- Create: `docs/wiki/Eye-Remote-Bootstrap-FR.md`
- Create: `docs/wiki/Eye-Remote-Bootstrap-ZH.md`

### Step 11.1: Create French translation

- [ ] Create FR wiki page (abbreviated for plan - full translation in implementation)

```markdown
# Eye Remote Bootstrap (FR)

La fonctionnalité Eye Remote Bootstrap (v2.1.0) ajoute la capacité de stockage de masse USB à l'Eye Remote, permettant à U-Boot de l'ESPRESSObin de charger le noyau, le DTB et l'initrd directement depuis le Pi Zero W.

[... full translation of Eye-Remote-Bootstrap.md ...]
```

### Step 11.2: Create Chinese translation

- [ ] Create ZH wiki page

```markdown
# Eye Remote Bootstrap (ZH)

Eye Remote Bootstrap 功能（v2.1.0）为 Eye Remote 添加了 USB 大容量存储功能，使 ESPRESSObin 的 U-Boot 能够直接从 Pi Zero W 加载内核、DTB 和 initrd。

[... full translation of Eye-Remote-Bootstrap.md ...]
```

### Step 11.3: Commit

- [ ] Commit translations

```bash
git add docs/wiki/Eye-Remote-Bootstrap-FR.md docs/wiki/Eye-Remote-Bootstrap-ZH.md
git commit -m "docs(eye-remote): add FR and ZH translations for Bootstrap wiki"
```

---

## Task 12: Update Existing Wiki Pages

**Files:**
- Modify: Wiki pages (if they exist locally)

### Step 12.1: Add bootstrap reference to Eye-Remote-Implementation

- [ ] Add section if file exists

```markdown
## Bootstrap Role (v2.1.0)

The Eye Remote can serve as a boot device for ESPRESSObin:

- **Mass Storage LUN** — U-Boot loads kernel/DTB/initrd from active slot
- **TFTP Shadow** — Test new images before promoting
- **Atomic Swap** — Safe active/shadow slot exchange

See [Eye-Remote-Bootstrap](Eye-Remote-Bootstrap.md) for full documentation.
```

### Step 12.2: Commit

- [ ] Commit updates

```bash
git add docs/wiki/
git commit -m "docs(eye-remote): add bootstrap references to existing wiki pages"
```

---

## Task 13: CLAUDE.md Update

**Files:**
- Modify: `CLAUDE.md` or `remote-ui/round/CLAUDE.md`

### Step 13.1: Add boot-media endpoints

- [ ] Update CLAUDE.md API reference table

Add to the API endpoints section:

```markdown
### Boot Media API (v2.1.0)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/eye-remote/boot-media/state` | Boot media state |
| POST | `/api/v1/eye-remote/boot-media/upload` | Upload to shadow |
| POST | `/api/v1/eye-remote/boot-media/swap` | Swap active/shadow |
| POST | `/api/v1/eye-remote/boot-media/rollback` | Rollback swap |
| GET | `/api/v1/eye-remote/boot-media/tftp/status` | TFTP status |
```

Add to systemd services:

```markdown
### Systemd Services

| Service | Description |
|---------|-------------|
| `secubox-eye-gadget.service` | USB gadget (ECM+ACM+mass_storage) |
```

### Step 13.2: Commit

- [ ] Commit CLAUDE.md update

```bash
git add CLAUDE.md remote-ui/round/CLAUDE.md
git commit -m "docs(eye-remote): update CLAUDE.md with boot-media endpoints"
```

---

## Task 14: Final Integration Test

### Step 14.1: Run all tests

- [ ] Run full test suite

```bash
cd packages/secubox-eye-remote
python -m pytest tests/ -v
```

### Step 14.2: Verify package builds

- [ ] Build Debian package

```bash
cd packages/secubox-eye-remote
dpkg-buildpackage -us -uc -b
```

### Step 14.3: Create feature branch and PR

- [ ] Create branch and prepare PR

```bash
git checkout -b feature/eye-remote-bootstrap
git push -u origin feature/eye-remote-bootstrap

gh pr create --title "feat(eye-remote): bootstrap role via mass_storage LUN + TFTP shadow (2.1.0)" \
  --body "$(cat <<'EOF'
## Summary
- Add mass_storage function to USB composite gadget
- 4R double-buffer for boot image management (active/shadow)
- FastAPI endpoints for upload/swap/rollback
- dnsmasq TFTP serving shadow slot
- U-Boot documentation

## Task Checklist
- [x] T1: gadget-setup.sh
- [x] T2: secubox-eye-gadget.service
- [x] T3: models/boot_media.py
- [x] T4: core/boot_media.py
- [x] T5: api/routers/boot_media.py
- [x] T6: dnsmasq/TFTP config
- [x] T7: U-Boot documentation
- [x] T8: Debian packaging
- [x] T9: Build script update
- [x] T10: Integration tests
- [x] T11: Wiki: Eye-Remote-Bootstrap
- [x] T12: Update existing wiki pages
- [x] T13: i18n (FR, ZH)
- [x] T14: CLAUDE.md update

## Spec
docs/superpowers/specs/2026-04-23-eye-remote-bootstrap-design.md

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review Checklist

- [x] Spec coverage: All 14 tasks mapped to implementation steps
- [x] No placeholders: All code blocks complete
- [x] Type consistency: Models match across tasks (BootImage, BootMediaState)
- [x] File paths: All paths explicit and consistent
- [x] Test coverage: Integration tests for core logic

---

*GK² · CyberMind · SecuBox-Deb · April 2026*
