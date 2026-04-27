"""
secubox_smart_strip — Host-side driver for SBX-STR-01 v1.1

Auto-detects USB CDC or I²C backend at instantiation. Exposes a single
SmartStrip API regardless of transport.

  USB CDC backend  : pyserial >= 3.5
  I²C backend      : smbus2 >= 0.4   (Linux only)

Hardware:
  https://github.com/cybermind/secubox-deb/blob/main/docs/hardware/smart-strip-v1.1.md

Quick start
-----------
    from secubox_smart_strip import SmartStrip, AUTH, WALL, BOOT, MIND, ROOT, MESH

    s = SmartStrip.auto()           # picks USB if present, else I²C
    s.set_led(AUTH, 0xC0, 0x4E, 0x24)
    s.set_all(0, 0, 0)
    s.anim(1)                        # Hamiltonian sweep
    print(s.touches())               # bitmask of currently touched pads
    s.heartbeat()                    # call every < 1 s to prevent panic mode

SecuBox / CyberMind - SBX-STR-01 v1.1
"""

from __future__ import annotations

import abc
import glob
import logging
import os
import struct
import threading
import time
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "SmartStrip",
    "UsbCdcBackend",
    "I2cBackend",
    "AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH",
    "SmartStripError",
]

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LED indices, named per SecuBox role
# ---------------------------------------------------------------------------
AUTH = 0
WALL = 1
BOOT = 2
MIND = 3
ROOT = 4
MESH = 5

LED_NAMES = ("AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH")

# Charte SecuBox couleurs par défaut (RGB triples)
CHARTE = {
    AUTH: (0xC0, 0x4E, 0x24),
    WALL: (0x9A, 0x60, 0x10),
    BOOT: (0x80, 0x30, 0x18),
    MIND: (0x3D, 0x35, 0xA0),
    ROOT: (0x0A, 0x58, 0x40),
    MESH: (0x10, 0x4A, 0x88),
}

# I²C device address (configurable via strap on PCB)
I2C_DEFAULT_ADDR = 0x42

# I²C register map (mirrored in firmware/include/registers.h)
REG_CTRL        = 0x00
REG_STATUS      = 0x01
REG_INT_FLAGS   = 0x02
REG_LED_BASE    = 0x10  # 0x10..0x22, 3 bytes per LED
REG_ANIM_ID     = 0x30
REG_HBT         = 0x40
REG_PANIC_CODE  = 0x50
REG_FW_VERSION  = 0xF0  # 3 bytes: major, minor, patch

USB_VID = 0x1209  # pid.codes
USB_PID = 0x4242  # placeholder; replace once allocated via pid.codes

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class SmartStripError(RuntimeError):
    """Raised on any backend communication error."""


# ---------------------------------------------------------------------------
# Backend abstract base
# ---------------------------------------------------------------------------

class _Backend(abc.ABC):
    """Internal transport abstraction. Don't use directly."""

    @abc.abstractmethod
    def set_led(self, idx: int, r: int, g: int, b: int) -> None: ...

    @abc.abstractmethod
    def set_all(self, r: int, g: int, b: int) -> None: ...

    @abc.abstractmethod
    def anim(self, anim_id: int) -> None: ...

    @abc.abstractmethod
    def heartbeat(self) -> None: ...

    @abc.abstractmethod
    def reset(self) -> None: ...

    @abc.abstractmethod
    def touches(self) -> int: ...

    @abc.abstractmethod
    def fw_version(self) -> tuple[int, int, int]: ...

    @abc.abstractmethod
    def close(self) -> None: ...


# ---------------------------------------------------------------------------
# USB CDC backend (pyserial)
# ---------------------------------------------------------------------------

class UsbCdcBackend(_Backend):
    """USB CDC ACM transport. Sends ASCII commands per the v1.1 BNF grammar."""

    def __init__(self, port: str, *, baudrate: int = 115200, timeout: float = 0.5):
        try:
            import serial  # noqa: F401  (lazy import)
        except ImportError as e:
            raise SmartStripError(
                "pyserial not installed; pip install pyserial"
            ) from e
        import serial
        self._ser = serial.Serial(port, baudrate=baudrate, timeout=timeout)
        self._lock = threading.Lock()
        # Drain any stale boot output.
        self._ser.reset_input_buffer()

    @classmethod
    def discover(cls) -> Optional[str]:
        """Find the first /dev/ttyACM* matching the VID/PID. None if absent."""
        try:
            import serial.tools.list_ports
        except ImportError:
            return None
        for p in serial.tools.list_ports.comports():
            if p.vid == USB_VID and (p.pid == USB_PID or p.pid is None):
                return p.device
        # Fallback: any ttyACM (legacy, less safe)
        for d in sorted(glob.glob("/dev/ttyACM*")):
            return d
        return None

    def _send(self, line: str) -> None:
        if not line.endswith("\n"):
            line += "\n"
        with self._lock:
            self._ser.write(line.encode("ascii"))
            self._ser.flush()

    def set_led(self, idx, r, g, b):
        _validate_idx(idx); _validate_rgb(r, g, b)
        self._send(f"SET_LED {idx} {r} {g} {b}")

    def set_all(self, r, g, b):
        _validate_rgb(r, g, b)
        self._send(f"SET_ALL {r} {g} {b}")

    def anim(self, anim_id):
        if not 0 <= anim_id <= 255:
            raise ValueError("anim_id 0..255")
        self._send(f"ANIM {anim_id}")

    def heartbeat(self):
        self._send("HBT")

    def reset(self):
        self._send("RESET")

    def touches(self) -> int:
        # Touch state arrives via HID interface, not CDC.
        # CDC backend cannot read touches; use evdev side-channel.
        # See SmartStrip.touches() which dispatches correctly.
        raise SmartStripError(
            "USB backend: read touches via HID/evdev, not CDC"
        )

    def fw_version(self):
        self._send("STATUS")
        # Reply format: "FW=major.minor.patch\n..."
        with self._lock:
            line = self._ser.readline().decode("ascii", errors="replace").strip()
        if not line.startswith("FW="):
            raise SmartStripError(f"unexpected STATUS reply: {line!r}")
        try:
            parts = line[3:].split(".")
            return tuple(int(x) for x in parts[:3])
        except ValueError as e:
            raise SmartStripError(f"bad FW version: {line!r}") from e

    def close(self):
        with self._lock:
            self._ser.close()


# ---------------------------------------------------------------------------
# I²C backend (smbus2)
# ---------------------------------------------------------------------------

class I2cBackend(_Backend):
    """I²C transport on /dev/i2c-N (Linux). Uses byte-block writes per register."""

    def __init__(self, bus: int = 1, address: int = I2C_DEFAULT_ADDR):
        try:
            from smbus2 import SMBus  # noqa: F401
        except ImportError as e:
            raise SmartStripError(
                "smbus2 not installed; pip install smbus2"
            ) from e
        from smbus2 import SMBus
        self._bus_num = bus
        self._addr = address
        self._bus = SMBus(bus)
        self._lock = threading.Lock()

    @classmethod
    def discover(cls, *, bus: int = 1, address: int = I2C_DEFAULT_ADDR) -> Optional[int]:
        """Return bus number if a Smart-Strip ACKs at `address`, else None."""
        try:
            from smbus2 import SMBus, i2c_msg
        except ImportError:
            return None
        if not os.path.exists(f"/dev/i2c-{bus}"):
            return None
        try:
            with SMBus(bus) as b:
                # Read FW_VERSION and check for plausible reply.
                b.write_byte(address, REG_FW_VERSION)
                data = b.read_i2c_block_data(address, REG_FW_VERSION, 3)
                # Sanity: major must be 1 for v1.x firmware
                if data[0] == 1:
                    return bus
        except Exception:
            return None
        return None

    def set_led(self, idx, r, g, b):
        _validate_idx(idx); _validate_rgb(r, g, b)
        with self._lock:
            self._bus.write_i2c_block_data(
                self._addr, REG_LED_BASE + idx * 3, [r, g, b]
            )

    def set_all(self, r, g, b):
        _validate_rgb(r, g, b)
        block = []
        for _ in range(6):
            block.extend([r, g, b])
        with self._lock:
            self._bus.write_i2c_block_data(self._addr, REG_LED_BASE, block)

    def anim(self, anim_id):
        if not 0 <= anim_id <= 255:
            raise ValueError("anim_id 0..255")
        with self._lock:
            self._bus.write_byte_data(self._addr, REG_ANIM_ID, anim_id)

    def heartbeat(self):
        with self._lock:
            self._bus.write_byte_data(self._addr, REG_HBT, 0x55)

    def reset(self):
        with self._lock:
            self._bus.write_byte_data(self._addr, REG_CTRL, 0x80)

    def touches(self) -> int:
        with self._lock:
            return self._bus.read_byte_data(self._addr, REG_STATUS) & 0x3F

    def fw_version(self):
        with self._lock:
            data = self._bus.read_i2c_block_data(self._addr, REG_FW_VERSION, 3)
        return (data[0], data[1], data[2])

    def close(self):
        with self._lock:
            self._bus.close()


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def _validate_idx(idx: int) -> None:
    if not 0 <= idx <= 5:
        raise ValueError(f"LED index must be 0..5, got {idx}")

def _validate_rgb(r: int, g: int, b: int) -> None:
    for v, name in ((r, "r"), (g, "g"), (b, "b")):
        if not 0 <= v <= 255:
            raise ValueError(f"{name} must be 0..255, got {v}")


# ---------------------------------------------------------------------------
# Public unified API
# ---------------------------------------------------------------------------

@dataclass
class SmartStrip:
    """High-level Smart-Strip handle. Construct via `SmartStrip.auto()`."""

    backend: _Backend

    @classmethod
    def auto(cls, *, prefer: str = "usb") -> "SmartStrip":
        """
        Auto-discover and connect.

        prefer = "usb" tries USB CDC first, falls back to I²C.
        prefer = "i2c" tries I²C first, falls back to USB CDC.
        Raises SmartStripError if no backend is reachable.
        """
        backends = ("usb", "i2c") if prefer == "usb" else ("i2c", "usb")
        for kind in backends:
            try:
                if kind == "usb":
                    port = UsbCdcBackend.discover()
                    if port:
                        log.info("SmartStrip: USB CDC at %s", port)
                        return cls(backend=UsbCdcBackend(port))
                else:
                    bus = I2cBackend.discover()
                    if bus is not None:
                        log.info("SmartStrip: I²C bus %d addr 0x%02X", bus, I2C_DEFAULT_ADDR)
                        return cls(backend=I2cBackend(bus=bus))
            except SmartStripError:
                continue
        raise SmartStripError(
            "no Smart-Strip found (no USB CDC matching VID 0x1209, no I²C ACK at 0x42)"
        )

    # --- Forwarders to backend ---

    def set_led(self, idx: int, r: int, g: int, b: int) -> None:
        self.backend.set_led(idx, r, g, b)

    def set_all(self, r: int, g: int, b: int) -> None:
        self.backend.set_all(r, g, b)

    def anim(self, anim_id: int) -> None:
        self.backend.anim(anim_id)

    def heartbeat(self) -> None:
        self.backend.heartbeat()

    def reset(self) -> None:
        self.backend.reset()

    def fw_version(self) -> tuple[int, int, int]:
        return self.backend.fw_version()

    def touches(self) -> int:
        """
        Return a 6-bit mask of currently touched pads (bit 0 = AUTH).

        For the I²C backend this is a polling read of REG_STATUS.
        For the USB backend, touches are HID events on /dev/input/event*;
        callers should subscribe via evdev rather than poll.
        """
        return self.backend.touches()

    def close(self) -> None:
        self.backend.close()

    # Context manager sugar
    def __enter__(self) -> "SmartStrip": return self
    def __exit__(self, *exc) -> None: self.close()


# ---------------------------------------------------------------------------
# Demo: heartbeat loop with charte palette
# ---------------------------------------------------------------------------

def _demo() -> None:
    """Run a 30-second visual smoke test of the connected Smart-Strip."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    with SmartStrip.auto() as s:
        log.info("FW version: %s", ".".join(map(str, s.fw_version())))
        # Light each LED in its charte color.
        for idx, name in enumerate(LED_NAMES):
            r, g, b = CHARTE[idx]
            s.set_led(idx, r, g, b)
            log.info("Lit %s = #%02X%02X%02X", name, r, g, b)
            time.sleep(0.4)
        # Heartbeat-driven idle for 20 s.
        deadline = time.time() + 20
        while time.time() < deadline:
            s.heartbeat()
            time.sleep(0.5)
        s.set_all(0, 0, 0)
        log.info("Smart-Strip demo done.")


if __name__ == "__main__":
    _demo()
