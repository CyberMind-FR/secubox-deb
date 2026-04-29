"""
SecuBox Eye Remote — Kwboot Protocol
Marvell Kirkwood/Armada serial boot protocol.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Kwboot Protocol:
- Used to boot Marvell SoCs when no valid bootloader is present
- Sends special boot pattern to trigger BootROM
- Transfers boot image via XMODEM
- Supports Armada 3720 (ESPRESSObin) and Armada 7040 (MOCHAbin)

Reference: https://github.com/u-boot/u-boot/blob/master/tools/kwboot.c
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable, Optional

from .xmodem import XmodemProtocol, XmodemStats

log = logging.getLogger(__name__)


class SoCType(Enum):
    """Supported Marvell SoC types."""
    ARMADA_3720 = auto()  # ESPRESSObin (32-bit boot)
    ARMADA_7040 = auto()  # MOCHAbin (64-bit boot via mvebu64boot)
    ARMADA_8040 = auto()  # Similar to 7040
    UNKNOWN = auto()


class KwbootState(Enum):
    """Kwboot protocol state machine."""
    IDLE = auto()
    SENDING_PATTERN = auto()
    WAITING_BOOTROM = auto()
    XMODEM_TRANSFER = auto()
    WAITING_PROMPT = auto()
    COMPLETE = auto()
    ERROR = auto()


@dataclass
class KwbootStats:
    """Kwboot transfer statistics."""
    state: KwbootState = KwbootState.IDLE
    pattern_count: int = 0
    pattern_total: int = 0
    bootrom_detected: bool = False
    xmodem: Optional[XmodemStats] = None
    error_message: str = ""
    elapsed_time: float = 0.0

    @property
    def progress(self) -> float:
        """Overall progress 0.0-1.0."""
        if self.state == KwbootState.SENDING_PATTERN:
            if self.pattern_total > 0:
                return 0.1 * (self.pattern_count / self.pattern_total)
            return 0.0
        elif self.state == KwbootState.WAITING_BOOTROM:
            return 0.1
        elif self.state == KwbootState.XMODEM_TRANSFER:
            if self.xmodem:
                return 0.1 + 0.8 * self.xmodem.progress
            return 0.1
        elif self.state == KwbootState.WAITING_PROMPT:
            return 0.9
        elif self.state == KwbootState.COMPLETE:
            return 1.0
        return 0.0


@dataclass
class KwbootConfig:
    """Kwboot configuration."""
    soc_type: SoCType = SoCType.ARMADA_3720
    baud_rate: int = 115200
    pattern_count: int = 100
    pattern_delay_ms: int = 10
    bootrom_timeout_s: float = 5.0
    prompt_timeout_s: float = 30.0
    prompt_pattern: bytes = b"Marvell>>"


# Boot patterns for different SoCs
BOOT_PATTERNS = {
    SoCType.ARMADA_3720: bytes([0xBB] * 8),  # Kirkwood/Armada 3720
    SoCType.ARMADA_7040: bytes([0xBB] * 8),  # Armada 7040/8040 (via mvebu64boot)
    SoCType.ARMADA_8040: bytes([0xBB] * 8),
}

# BootROM response signatures
BOOTROM_SIGNATURES = {
    SoCType.ARMADA_3720: [
        b"BootROM",
        b"BOOTROM",
        b"bootrom",
        b"\x11\x22",  # Armada 3720 ACK pattern
    ],
    SoCType.ARMADA_7040: [
        b"BootROM",
        b"A7K",
        b"ARMADA",
    ],
    SoCType.ARMADA_8040: [
        b"BootROM",
        b"A8K",
    ],
}


class KwbootProtocol:
    """
    Marvell kwboot serial boot protocol.

    Flow:
    1. Send boot pattern repeatedly to trigger BootROM
    2. Wait for BootROM acknowledgment
    3. Transfer boot image via XMODEM
    4. Wait for U-Boot prompt (optional)
    """

    def __init__(
        self,
        read_func: Callable[[], bytes],
        write_func: Callable[[bytes], None],
        config: Optional[KwbootConfig] = None,
    ):
        """
        Initialize kwboot protocol.

        Args:
            read_func: Function to read bytes from serial
            write_func: Function to write bytes to serial
            config: Protocol configuration
        """
        self.read = read_func
        self.write = write_func
        self.config = config or KwbootConfig()
        self.stats = KwbootStats(pattern_total=self.config.pattern_count)
        self._cancelled = False
        self._start_time = 0.0

    def cancel(self) -> None:
        """Cancel ongoing operation."""
        self._cancelled = True

    def _get_boot_pattern(self) -> bytes:
        """Get boot pattern for configured SoC."""
        return BOOT_PATTERNS.get(self.config.soc_type, BOOT_PATTERNS[SoCType.ARMADA_3720])

    def _check_bootrom_response(self, data: bytes) -> bool:
        """Check if data contains BootROM signature."""
        signatures = BOOTROM_SIGNATURES.get(
            self.config.soc_type,
            BOOTROM_SIGNATURES[SoCType.ARMADA_3720]
        )
        for sig in signatures:
            if sig in data:
                return True
        return False

    async def send_boot_pattern(
        self,
        progress_callback: Optional[Callable[[KwbootStats], None]] = None,
    ) -> bool:
        """
        Send boot pattern to trigger BootROM.

        Args:
            progress_callback: Optional progress callback

        Returns:
            True if BootROM acknowledged
        """
        self._cancelled = False
        self._start_time = time.time()
        self.stats = KwbootStats(
            state=KwbootState.SENDING_PATTERN,
            pattern_total=self.config.pattern_count,
        )

        pattern = self._get_boot_pattern()
        delay_s = self.config.pattern_delay_ms / 1000.0

        log.info(f"Sending boot pattern ({len(pattern)} bytes) x {self.config.pattern_count}")

        # Buffer for incoming data
        recv_buffer = bytearray()

        for i in range(self.config.pattern_count):
            if self._cancelled:
                self.stats.state = KwbootState.ERROR
                self.stats.error_message = "Cancelled"
                return False

            # Send pattern
            self.write(pattern)
            self.stats.pattern_count = i + 1
            self.stats.elapsed_time = time.time() - self._start_time

            if progress_callback:
                progress_callback(self.stats)

            # Check for response (non-blocking)
            try:
                data = self.read()
                if data:
                    recv_buffer.extend(data)
                    if self._check_bootrom_response(recv_buffer):
                        log.info("BootROM detected!")
                        self.stats.bootrom_detected = True
                        self.stats.state = KwbootState.WAITING_BOOTROM
                        return True
            except Exception as e:
                log.debug(f"Read during pattern: {e}")

            await asyncio.sleep(delay_s)

        # Didn't get BootROM response during pattern phase
        # Wait a bit longer for response
        self.stats.state = KwbootState.WAITING_BOOTROM
        deadline = time.time() + self.config.bootrom_timeout_s

        log.debug("Waiting for BootROM response...")
        while time.time() < deadline:
            if self._cancelled:
                self.stats.state = KwbootState.ERROR
                self.stats.error_message = "Cancelled"
                return False

            try:
                data = self.read()
                if data:
                    recv_buffer.extend(data)
                    if self._check_bootrom_response(recv_buffer):
                        log.info("BootROM detected!")
                        self.stats.bootrom_detected = True
                        return True
            except Exception as e:
                log.debug(f"Read error: {e}")

            self.stats.elapsed_time = time.time() - self._start_time
            if progress_callback:
                progress_callback(self.stats)

            await asyncio.sleep(0.05)

        self.stats.state = KwbootState.ERROR
        self.stats.error_message = "BootROM not detected"
        log.warning("BootROM not detected within timeout")
        return False

    async def send_image(
        self,
        image_data: bytes,
        progress_callback: Optional[Callable[[KwbootStats], None]] = None,
    ) -> bool:
        """
        Send boot image via XMODEM after BootROM detection.

        Args:
            image_data: Boot image data
            progress_callback: Optional progress callback

        Returns:
            True if transfer successful
        """
        if not self.stats.bootrom_detected:
            log.error("Cannot send image: BootROM not detected")
            return False

        self.stats.state = KwbootState.XMODEM_TRANSFER
        log.info(f"Starting XMODEM transfer: {len(image_data)} bytes")

        # Create XMODEM protocol instance
        xmodem = XmodemProtocol(self.read, self.write, block_size=128)

        def xmodem_progress(stats: XmodemStats):
            self.stats.xmodem = stats
            self.stats.elapsed_time = time.time() - self._start_time
            if progress_callback:
                progress_callback(self.stats)

        success = await xmodem.send(image_data, progress_callback=xmodem_progress)

        if success:
            self.stats.state = KwbootState.WAITING_PROMPT
            log.info("XMODEM transfer complete")
        else:
            self.stats.state = KwbootState.ERROR
            self.stats.error_message = "XMODEM transfer failed"
            log.error("XMODEM transfer failed")

        return success

    async def wait_for_prompt(
        self,
        progress_callback: Optional[Callable[[KwbootStats], None]] = None,
    ) -> bool:
        """
        Wait for U-Boot prompt after image transfer.

        Args:
            progress_callback: Optional progress callback

        Returns:
            True if prompt detected
        """
        self.stats.state = KwbootState.WAITING_PROMPT
        deadline = time.time() + self.config.prompt_timeout_s
        recv_buffer = bytearray()

        log.info(f"Waiting for prompt: {self.config.prompt_pattern}")

        while time.time() < deadline:
            if self._cancelled:
                self.stats.state = KwbootState.ERROR
                self.stats.error_message = "Cancelled"
                return False

            try:
                data = self.read()
                if data:
                    recv_buffer.extend(data)
                    # Log received output
                    try:
                        log.debug(f"Boot output: {data.decode('ascii', errors='replace')}")
                    except Exception:
                        pass

                    if self.config.prompt_pattern in recv_buffer:
                        log.info("U-Boot prompt detected!")
                        self.stats.state = KwbootState.COMPLETE
                        return True
            except Exception as e:
                log.debug(f"Read error: {e}")

            self.stats.elapsed_time = time.time() - self._start_time
            if progress_callback:
                progress_callback(self.stats)

            await asyncio.sleep(0.1)

        log.warning("Prompt not detected within timeout")
        # Not necessarily an error - the image might be executing
        self.stats.state = KwbootState.COMPLETE
        return True

    async def boot(
        self,
        image_data: bytes,
        wait_prompt: bool = True,
        progress_callback: Optional[Callable[[KwbootStats], None]] = None,
    ) -> bool:
        """
        Complete kwboot sequence: pattern → XMODEM → prompt.

        Args:
            image_data: Boot image data
            wait_prompt: Wait for U-Boot prompt after transfer
            progress_callback: Optional progress callback

        Returns:
            True if boot successful
        """
        log.info(f"Starting kwboot sequence for {self.config.soc_type.name}")

        # Send boot pattern
        if not await self.send_boot_pattern(progress_callback):
            return False

        # Send image via XMODEM
        if not await self.send_image(image_data, progress_callback):
            return False

        # Wait for prompt (optional)
        if wait_prompt:
            await self.wait_for_prompt(progress_callback)

        self.stats.state = KwbootState.COMPLETE
        self.stats.elapsed_time = time.time() - self._start_time

        if progress_callback:
            progress_callback(self.stats)

        log.info(f"Kwboot complete in {self.stats.elapsed_time:.1f}s")
        return True

    @staticmethod
    def detect_soc_type(serial_output: bytes) -> SoCType:
        """
        Detect SoC type from serial output.

        Args:
            serial_output: Boot output from serial port

        Returns:
            Detected SoC type
        """
        output = serial_output.lower()

        if b"a3720" in output or b"armada 3720" in output or b"espressobin" in output:
            return SoCType.ARMADA_3720
        elif b"a7040" in output or b"armada 7040" in output or b"mochabin" in output:
            return SoCType.ARMADA_7040
        elif b"a8040" in output or b"armada 8040" in output:
            return SoCType.ARMADA_8040

        return SoCType.UNKNOWN
