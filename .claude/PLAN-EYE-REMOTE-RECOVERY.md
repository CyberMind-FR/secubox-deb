# Eye Remote Recovery Boot System — Plan

## Overview

**Goal:** Extend Eye Remote Pi Zero W to provide full Marvell board recovery capabilities via USB serial emulation, including kwboot, U-Boot flashing, and automated recovery workflows.

**Target Boards:**
- MOCHAbin (Armada 7040)
- ESPRESSObin v7 (Armada 3720)
- ESPRESSObin Ultra (Armada 3720)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Eye Remote Pi Zero W                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │
│  │ USB Gadget  │  │   Serial    │  │   Storage   │  │  Display   │ │
│  │  ECM+ACM+   │  │  /dev/ttyGS0│  │  mass_stor  │  │  GC9A01    │ │
│  │  mass_stor  │  │  115200baud │  │  boot.img   │  │  240x240   │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬──────┘ │
│         │                │                │                │        │
│  ┌──────┴────────────────┴────────────────┴────────────────┴──────┐ │
│  │                    Recovery Controller                         │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │ │
│  │  │ kwboot   │  │ U-Boot   │  │ Tow-Boot │  │ mvebu64boot  │   │ │
│  │  │ emulator │  │ flasher  │  │ UEFI     │  │ MOCHAbin     │   │ │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────────┘   │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ USB-C (OTG)
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Target Marvell Board                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐│
│  │ UART     │  │ USB OTG  │  │ eMMC/SD  │  │ Boot ROM             ││
│  │ Console  │  │ Port     │  │ Storage  │  │ (BootROM → kwboot)   ││
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
```

---

## Boot Modes

### 1. Normal Mode (NORMAL)
Standard dashboard display with metrics from SecuBox hub.

### 2. TTY Mode (TTY)
Serial console pass-through for U-Boot/Linux boot monitoring.

### 3. Flash Mode (FLASH)
USB mass storage transfer progress for eMMC/SD flashing.

### 4. Recovery Mode (RECOVERY) — **NEW**
Full board recovery with kwboot/mochatools integration.

### 5. UEFI Mode (UEFI) — **NEW**
Tow-Boot UEFI firmware installation for MOCHAbin.

---

## Recovery Tools Integration

### kwboot (Kirkwood/Marvell Serial Boot)

**Purpose:** Boot Marvell SoCs via UART when no bootloader is present (bricked boards).

**How it works:**
1. Board in BootROM mode (no valid bootloader)
2. kwboot sends special boot pattern over UART at 115200 baud
3. BootROM accepts boot image via XMODEM
4. U-Boot/recovery image loads into RAM and executes

**Eye Remote Implementation:**
```python
class KwbootEmulator:
    """Emulate kwboot serial boot protocol over /dev/ttyGS0."""

    BOOT_PATTERN = bytes([0xBB] * 8)  # Marvell boot pattern
    XMODEM_SOH = 0x01
    XMODEM_EOT = 0x04
    XMODEM_ACK = 0x06
    XMODEM_NAK = 0x15

    def __init__(self, serial_port: str, boot_image: Path):
        self.port = serial.Serial(serial_port, 115200)
        self.image = boot_image.read_bytes()

    def send_boot_pattern(self):
        """Send boot pattern to trigger BootROM."""
        for _ in range(100):
            self.port.write(self.BOOT_PATTERN)
            time.sleep(0.01)

    def xmodem_send(self):
        """Send boot image via XMODEM protocol."""
        # ... XMODEM implementation
```

### mochatools (MOCHAbin Tools)

**Purpose:** MOCHAbin-specific tools for board recovery and configuration.

**Components:**
- `mocha-flash`: Flash U-Boot to SPI NOR
- `mocha-rescue`: Enter rescue mode via GPIO
- `mocha-config`: Configure boot switches

**Eye Remote Implementation:**
```bash
# GPIO control for rescue mode (via Pi Zero GPIOs)
# MOCHAbin has recovery mode triggered by specific GPIO states

# Recovery sequence:
# 1. Assert RESCUE pin
# 2. Power cycle board
# 3. Board enters BootROM mode
# 4. Use kwboot to load recovery image
```

### Tow-Boot UEFI

**Purpose:** Modern UEFI firmware for Armada boards, replacing U-Boot.

**Benefits:**
- Standard UEFI boot flow
- Secure Boot support
- EFI system partition
- GRUB/systemd-boot compatibility

**Supported Boards:**
- MOCHAbin (mvebu64boot)
- Pine64 boards
- Rockchip boards

**Eye Remote Integration:**
```
/srv/secubox-recovery/
├── uboot/
│   ├── espressobin-v7-uboot.bin
│   ├── espressobin-ultra-uboot.bin
│   └── mochabin-uboot.bin
├── towboot/
│   ├── mochabin-towboot.img
│   └── espressobin-towboot.img (if available)
├── rescue/
│   ├── rescue-initramfs.cpio.gz
│   └── rescue-kernel.img
└── tools/
    ├── kwboot
    ├── mocha-flash
    └── mvebu64boot
```

### mvebu64boot (Marvell EBU 64-bit Boot)

**Purpose:** Boot loader for Armada 8K/7K platforms via UART.

**Similar to kwboot but for:**
- Armada 7040 (MOCHAbin)
- Armada 8040

---

## Display Modes for Recovery

### RECOVERY Mode Display

```
┌──────────────────────────────────┐
│         RECOVERY MODE            │
│                                  │
│    ┌──────────────────────┐     │
│    │    BOARD: MOCHAbin   │     │
│    │    STATE: BootROM    │     │
│    │                      │     │
│    │  [████████░░] 80%    │     │
│    │  Sending U-Boot...   │     │
│    └──────────────────────┘     │
│                                  │
│  ○ DETECT  ○ KWBOOT  ● XMODEM   │
└──────────────────────────────────┘
```

### UEFI Mode Display

```
┌──────────────────────────────────┐
│          UEFI INSTALL            │
│                                  │
│    ┌──────────────────────┐     │
│    │   Tow-Boot UEFI      │     │
│    │   v2024.07           │     │
│    │                      │     │
│    │  [██████████] 100%   │     │
│    │  Complete!           │     │
│    └──────────────────────┘     │
│                                  │
│  Reboot to enter UEFI setup     │
└──────────────────────────────────┘
```

---

## Implementation Plan

### Phase 1: Recovery Controller Service

**File:** `remote-ui/round/recovery_controller.py`

```python
"""
SecuBox-DEB :: Eye Remote Recovery Controller
CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""

import asyncio
import serial
from pathlib import Path
from enum import Enum, auto
from dataclasses import dataclass

class BoardType(Enum):
    MOCHABIN = auto()
    ESPRESSOBIN_V7 = auto()
    ESPRESSOBIN_ULTRA = auto()
    UNKNOWN = auto()

class RecoveryState(Enum):
    IDLE = auto()
    DETECTING = auto()
    BOOTROM_DETECTED = auto()
    KWBOOT_SENDING = auto()
    XMODEM_TRANSFER = auto()
    UBOOT_PROMPT = auto()
    FLASHING = auto()
    COMPLETE = auto()
    ERROR = auto()

@dataclass
class RecoveryStatus:
    state: RecoveryState
    board: BoardType
    progress: float
    message: str
    error: str | None = None

class RecoveryController:
    """Main recovery controller for Eye Remote."""

    SERIAL_PORT = "/dev/ttyGS0"
    BAUD_RATE = 115200
    RECOVERY_DIR = Path("/srv/secubox-recovery")

    def __init__(self):
        self.status = RecoveryStatus(
            state=RecoveryState.IDLE,
            board=BoardType.UNKNOWN,
            progress=0.0,
            message="Ready"
        )
        self.serial: serial.Serial | None = None

    async def detect_board(self) -> BoardType:
        """Detect board type from serial output."""
        self.status.state = RecoveryState.DETECTING
        self.status.message = "Detecting board..."

        # Read serial output and match patterns
        # MOCHAbin: "Marvell>> " or "ARMADA 7040"
        # ESPRESSObin: "Marvell>> " or "ARMADA 3720"

        # If no bootloader output, check for BootROM pattern
        ...

    async def kwboot_recovery(self, image: Path) -> bool:
        """Perform kwboot recovery sequence."""
        self.status.state = RecoveryState.KWBOOT_SENDING
        self.status.message = "Sending boot pattern..."

        # 1. Send boot pattern
        # 2. Wait for BootROM acknowledgment
        # 3. Switch to XMODEM transfer
        ...

    async def xmodem_send(self, data: bytes) -> bool:
        """Send data via XMODEM protocol."""
        self.status.state = RecoveryState.XMODEM_TRANSFER

        # Standard XMODEM with CRC
        block_size = 128
        total_blocks = (len(data) + block_size - 1) // block_size

        for i in range(total_blocks):
            # Send block
            # Wait for ACK
            self.status.progress = (i + 1) / total_blocks
            ...

    async def flash_uboot(self, image: Path) -> bool:
        """Flash U-Boot to board storage."""
        self.status.state = RecoveryState.FLASHING

        # 1. Load image to RAM via XMODEM or TFTP
        # 2. Send U-Boot commands to flash
        # sf probe 0
        # sf erase 0 0x200000
        # sf write 0x4000000 0 0x200000
        ...

    async def install_towboot(self) -> bool:
        """Install Tow-Boot UEFI firmware."""
        # Similar to flash_uboot but with UEFI image
        ...
```

### Phase 2: Serial Protocol Handlers

**File:** `remote-ui/round/protocols/kwboot.py`

```python
"""kwboot protocol implementation."""

import struct
from typing import Generator

class KwbootProtocol:
    """Marvell kwboot serial boot protocol."""

    # Boot patterns for different SoCs
    PATTERNS = {
        'armada3720': bytes([0xBB] * 8),  # ESPRESSObin
        'armada7040': bytes([0xBB] * 8),  # MOCHAbin
    }

    # Timing
    PATTERN_DELAY = 0.01  # 10ms between patterns
    PATTERN_COUNT = 100   # Number of patterns to send
    TIMEOUT = 5.0         # Timeout waiting for response

    def generate_pattern(self, soc: str) -> Generator[bytes, None, None]:
        """Generate boot pattern sequence."""
        pattern = self.PATTERNS.get(soc, self.PATTERNS['armada3720'])
        for _ in range(self.PATTERN_COUNT):
            yield pattern

    def parse_response(self, data: bytes) -> dict:
        """Parse BootROM response."""
        # BootROM sends acknowledgment when ready for XMODEM
        ...
```

**File:** `remote-ui/round/protocols/xmodem.py`

```python
"""XMODEM protocol implementation."""

class XmodemProtocol:
    """Standard XMODEM with CRC."""

    SOH = 0x01  # Start of header (128 byte block)
    STX = 0x02  # Start of header (1024 byte block)
    EOT = 0x04  # End of transmission
    ACK = 0x06  # Acknowledge
    NAK = 0x15  # Negative acknowledge
    CAN = 0x18  # Cancel
    CRC = 0x43  # 'C' for CRC mode

    def __init__(self, block_size: int = 128):
        self.block_size = block_size

    def make_block(self, seq: int, data: bytes) -> bytes:
        """Create XMODEM block with CRC."""
        header = bytes([self.SOH, seq & 0xFF, 0xFF - (seq & 0xFF)])
        padded = data.ljust(self.block_size, b'\x1A')
        crc = self._calc_crc(padded)
        return header + padded + struct.pack('>H', crc)

    def _calc_crc(self, data: bytes) -> int:
        """Calculate CRC-16-CCITT."""
        crc = 0
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ 0x1021
                else:
                    crc <<= 1
        return crc & 0xFFFF
```

### Phase 3: Display Integration

**File:** `remote-ui/round/fb_dashboard.py` (additions)

```python
class RecoveryDisplay:
    """Recovery mode display for Eye Remote."""

    def draw_recovery_mode(self, status: RecoveryStatus):
        """Draw recovery mode display."""
        self.draw.rectangle([0, 0, 240, 240], fill=self.COSMOS_BLACK)

        # Title
        self.draw.text((120, 20), "RECOVERY MODE",
                       fill=self.CINNABAR, font=self.font_title, anchor="mm")

        # Board type
        board_name = status.board.name.replace('_', ' ')
        self.draw.text((120, 60), f"BOARD: {board_name}",
                       fill=self.TEXT_PRIMARY, font=self.font_medium, anchor="mm")

        # State
        state_name = status.state.name.replace('_', ' ')
        self.draw.text((120, 85), f"STATE: {state_name}",
                       fill=self.MATRIX_GREEN, font=self.font_small, anchor="mm")

        # Progress bar
        self._draw_progress_bar(120, 130, 160, 20, status.progress)

        # Message
        self.draw.text((120, 170), status.message,
                       fill=self.TEXT_PRIMARY, font=self.font_small, anchor="mm")

        # Status indicators
        self._draw_status_indicators(status.state)

    def _draw_progress_bar(self, cx, cy, width, height, progress):
        """Draw centered progress bar."""
        x1 = cx - width // 2
        y1 = cy - height // 2
        x2 = cx + width // 2
        y2 = cy + height // 2

        # Border
        self.draw.rectangle([x1, y1, x2, y2], outline=self.GOLD_HERMETIC, width=2)

        # Fill
        fill_width = int((width - 4) * progress)
        if fill_width > 0:
            self.draw.rectangle([x1 + 2, y1 + 2, x1 + 2 + fill_width, y2 - 2],
                               fill=self.MATRIX_GREEN)

        # Percentage
        self.draw.text((cx, cy), f"{int(progress * 100)}%",
                       fill=self.TEXT_PRIMARY, font=self.font_small, anchor="mm")
```

### Phase 4: Systemd Services

**File:** `remote-ui/round/systemd/secubox-eye-recovery.service`

```ini
[Unit]
Description=SecuBox Eye Remote Recovery Controller
After=secubox-eye-gadget.service
Requires=secubox-eye-gadget.service
PartOf=secubox-eye-gadget.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/secubox-eye/recovery_controller.py
Restart=on-failure
RestartSec=5

Environment=PYTHONUNBUFFERED=1
Environment=RECOVERY_DIR=/srv/secubox-recovery

[Install]
WantedBy=multi-user.target
```

### Phase 5: Recovery Image Storage

**Directory Structure:**
```
/srv/secubox-recovery/
├── boards/
│   ├── mochabin/
│   │   ├── uboot-spi.bin           # U-Boot for SPI NOR
│   │   ├── uboot-mmc.bin           # U-Boot for eMMC
│   │   ├── towboot.img             # Tow-Boot UEFI
│   │   └── rescue-initramfs.img    # Rescue system
│   ├── espressobin-v7/
│   │   ├── uboot-spi.bin
│   │   ├── uboot-mmc.bin
│   │   └── rescue-initramfs.img
│   └── espressobin-ultra/
│       ├── uboot-spi.bin
│       └── rescue-initramfs.img
├── tools/
│   ├── kwboot                      # Compiled kwboot binary (ARM)
│   ├── mvebu64boot                 # Marvell 64-bit boot tool
│   └── mocha-flash                 # MOCHAbin flash script
└── config/
    ├── boards.json                 # Board detection signatures
    └── recovery-flows.json         # Recovery workflow definitions
```

### Phase 6: WebSocket API for Recovery

**File:** `remote-ui/round/api/recovery_api.py`

```python
"""Recovery API endpoints for WebSocket control."""

from fastapi import APIRouter, WebSocket
from ..recovery_controller import RecoveryController

router = APIRouter(prefix="/api/v1/recovery")
controller = RecoveryController()

@router.get("/status")
async def get_status():
    """Get current recovery status."""
    return {
        "state": controller.status.state.name,
        "board": controller.status.board.name,
        "progress": controller.status.progress,
        "message": controller.status.message,
        "error": controller.status.error
    }

@router.post("/detect")
async def detect_board():
    """Trigger board detection."""
    board = await controller.detect_board()
    return {"board": board.name}

@router.post("/kwboot")
async def start_kwboot(board: str, image: str):
    """Start kwboot recovery."""
    # ...

@router.post("/flash")
async def flash_firmware(board: str, target: str, image: str):
    """Flash firmware to board."""
    # target: spi, mmc, uefi

@router.websocket("/ws")
async def recovery_websocket(websocket: WebSocket):
    """WebSocket for real-time recovery updates."""
    await websocket.accept()
    while True:
        await websocket.send_json({
            "state": controller.status.state.name,
            "progress": controller.status.progress,
            "message": controller.status.message
        })
        await asyncio.sleep(0.1)
```

---

## Automated Recovery Workflows

### Workflow 1: Full Board Recovery (Bricked)

```
┌─────────────────────────────────────────────────────────────────┐
│  1. DETECT    │  2. KWBOOT    │  3. FLASH     │  4. VERIFY    │
│  ───────────  │  ───────────  │  ───────────  │  ───────────  │
│  Scan serial  │  Send boot    │  Load U-Boot  │  Reboot and   │
│  for BootROM  │  pattern +    │  to SPI NOR   │  verify boot  │
│  signature    │  XMODEM img   │  via commands │  sequence     │
└─────────────────────────────────────────────────────────────────┘
```

### Workflow 2: U-Boot Upgrade

```
┌─────────────────────────────────────────────────────────────────┐
│  1. CONNECT   │  2. BACKUP    │  3. FLASH     │  4. VERIFY    │
│  ───────────  │  ───────────  │  ───────────  │  ───────────  │
│  Wait for     │  Read current │  Write new    │  Reset and    │
│  U-Boot       │  U-Boot from  │  U-Boot to    │  verify new   │
│  prompt       │  SPI NOR      │  SPI NOR      │  version      │
└─────────────────────────────────────────────────────────────────┘
```

### Workflow 3: Tow-Boot UEFI Install

```
┌─────────────────────────────────────────────────────────────────┐
│  1. PREPARE   │  2. PARTITION │  3. INSTALL   │  4. CONFIGURE │
│  ───────────  │  ───────────  │  ───────────  │  ───────────  │
│  Boot to      │  Create EFI   │  Write        │  Set boot     │
│  rescue       │  System       │  Tow-Boot     │  variables    │
│  system       │  Partition    │  to ESP       │  via efivar   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Files to Create

| File | Description |
|------|-------------|
| `remote-ui/round/recovery_controller.py` | Main recovery controller |
| `remote-ui/round/protocols/kwboot.py` | kwboot protocol implementation |
| `remote-ui/round/protocols/xmodem.py` | XMODEM protocol implementation |
| `remote-ui/round/protocols/mvebu64.py` | mvebu64boot protocol |
| `remote-ui/round/api/recovery_api.py` | FastAPI recovery endpoints |
| `remote-ui/round/systemd/secubox-eye-recovery.service` | Systemd service |
| `remote-ui/round/display/recovery_display.py` | Recovery display modes |

## Dependencies

```
# Python packages
pyserial>=3.5
crcmod>=1.7  # For CRC calculations

# System packages (ARM)
kwboot  # From U-Boot tools
mtools  # For FAT filesystem operations
```

---

## Security Considerations

1. **Recovery images signed** with GPG keys
2. **Serial access** requires physical presence (USB connection)
3. **Firmware verification** via SHA256 checksums
4. **Audit logging** of all recovery operations
5. **No network access** during recovery (air-gapped)

---

## Estimated Scope

- **New files:** 7 Python modules + 1 service
- **Lines of code:** ~1500-2000
- **Complexity:** High (serial protocols, low-level boot)
- **Dependencies:** pyserial, crcmod

---

## References

- [kwboot source](https://github.com/u-boot/u-boot/blob/master/tools/kwboot.c)
- [Tow-Boot](https://tow-boot.org/)
- [Marvell BootROM](https://wiki.kobol.io/helios64/bootrom/)
- [ESPRESSObin recovery](https://wiki.solid-run.com/doku.php?id=products:a3700:software:development:boot_from_uart)
- [MOCHAbin docs](https://globalscaletechnologies.com/product/mochabin/)
