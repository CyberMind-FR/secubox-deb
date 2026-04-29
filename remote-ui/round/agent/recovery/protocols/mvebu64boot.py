"""
SecuBox Eye Remote — Mvebu64boot Protocol
64-bit Marvell EBU SoC serial boot protocol for Armada 7040/8040.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Mvebu64boot Protocol (ported from mvebu64boot.c by Pali Rohár):
- Used to boot 64-bit Marvell SoCs (Armada 7040/8040) via UART
- Different boot pattern than kwboot (for 32-bit Armada 3720)
- Uses XMODEM with checksum (not CRC-16)
- Validates image header with magic 0xB105B002

Reference: https://github.com/pali/mvebu64boot
"""
from __future__ import annotations

import asyncio
import logging
import struct
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable, Optional

log = logging.getLogger(__name__)


# XMODEM control characters
SOH = 0x01  # Start of header (128 byte block)
EOT = 0x04  # End of transmission
ACK = 0x06  # Acknowledge
NAK = 0x15  # Negative acknowledge

XMODEM_BLOCK_SIZE = 128
MAIN_HDR_MAGIC = 0xB105B002

# Boot pattern for Armada 7040/8040 (different from kwboot 0xBB*8)
BOOT_PATTERN_64 = bytes([0xBB, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77])


class Mvebu64State(Enum):
    """Mvebu64boot protocol state machine."""
    IDLE = auto()
    SENDING_PATTERN = auto()
    WAITING_NAK = auto()
    SENDING_SYNC = auto()
    XMODEM_PROLOG = auto()
    XMODEM_BOOTLOADER = auto()
    XMODEM_FINISH = auto()
    WAITING_BOOTROM = auto()
    COMPLETE = auto()
    ERROR = auto()


@dataclass
class MainHeader:
    """Marvell boot image main header (64 bytes)."""
    magic: int                # 0x00-0x03: 0xB105B002
    prolog_size: int          # 0x04-0x07
    prolog_checksum: int      # 0x08-0x0b
    bl_image_size: int        # 0x0c-0x0f
    bl_image_checksum: int    # 0x10-0x13
    reserved1: int            # 0x14-0x17
    load_addr: int            # 0x18-0x1b
    exec_addr: int            # 0x1c-0x1f
    uart_cfg: int             # 0x20
    baudrate: int             # 0x21
    ext_cnt: int              # 0x22
    aux_flags: int            # 0x23
    nand_block_size: int      # 0x24
    nand_cell_type: int       # 0x25
    # reserved2[26]           # 0x26-0x3f

    @classmethod
    def from_bytes(cls, data: bytes) -> "MainHeader":
        """Parse header from bytes."""
        if len(data) < 64:
            raise ValueError("Header too small")

        return cls(
            magic=struct.unpack_from("<I", data, 0)[0],
            prolog_size=struct.unpack_from("<I", data, 4)[0],
            prolog_checksum=struct.unpack_from("<I", data, 8)[0],
            bl_image_size=struct.unpack_from("<I", data, 12)[0],
            bl_image_checksum=struct.unpack_from("<I", data, 16)[0],
            reserved1=struct.unpack_from("<I", data, 20)[0],
            load_addr=struct.unpack_from("<I", data, 24)[0],
            exec_addr=struct.unpack_from("<I", data, 28)[0],
            uart_cfg=data[32],
            baudrate=data[33],
            ext_cnt=data[34],
            aux_flags=data[35],
            nand_block_size=data[36],
            nand_cell_type=data[37],
        )


@dataclass
class Mvebu64Stats:
    """Transfer statistics."""
    state: Mvebu64State = Mvebu64State.IDLE
    prolog_bytes: int = 0
    prolog_total: int = 0
    bootloader_bytes: int = 0
    bootloader_total: int = 0
    blocks_sent: int = 0
    blocks_total: int = 0
    retries: int = 0
    error_message: str = ""
    elapsed_time: float = 0.0

    @property
    def progress(self) -> float:
        """Overall progress 0.0-1.0."""
        if self.state == Mvebu64State.SENDING_PATTERN:
            return 0.05
        elif self.state == Mvebu64State.WAITING_NAK:
            return 0.08
        elif self.state == Mvebu64State.SENDING_SYNC:
            return 0.10
        elif self.state == Mvebu64State.XMODEM_PROLOG:
            if self.prolog_total > 0:
                return 0.1 + 0.3 * (self.prolog_bytes / self.prolog_total)
            return 0.1
        elif self.state == Mvebu64State.XMODEM_BOOTLOADER:
            if self.bootloader_total > 0:
                return 0.4 + 0.5 * (self.bootloader_bytes / self.bootloader_total)
            return 0.4
        elif self.state == Mvebu64State.XMODEM_FINISH:
            return 0.95
        elif self.state == Mvebu64State.COMPLETE:
            return 1.0
        return 0.0


@dataclass
class Mvebu64Config:
    """Mvebu64boot configuration."""
    baud_rate: int = 115200
    pattern_repeat: int = 128
    pattern_interval_ms: int = 24
    nak_timeout_ms: int = 10000
    ack_timeout_ms: int = 2000
    max_retries: int = 16


class Mvebu64Protocol:
    """
    64-bit Marvell EBU serial boot protocol.

    Protocol flow:
    1. Send boot pattern repeatedly until NAK received
    2. Send sync sequence (0xFF * 132 bytes)
    3. Transfer prolog via XMODEM (with output allowed on last ACK)
    4. Transfer bootloader via XMODEM
    5. Send EOT and wait for ACK
    """

    def __init__(
        self,
        read_func: Callable[[], bytes],
        write_func: Callable[[bytes], None],
        config: Optional[Mvebu64Config] = None,
    ):
        """
        Initialize mvebu64boot protocol.

        Args:
            read_func: Function to read bytes from serial
            write_func: Function to write bytes to serial
            config: Protocol configuration
        """
        self.read = read_func
        self.write = write_func
        self.config = config or Mvebu64Config()
        self.stats = Mvebu64Stats()
        self._cancelled = False
        self._start_time = 0.0
        self._seq = 1  # XMODEM sequence number

    def cancel(self) -> None:
        """Cancel ongoing operation."""
        self._cancelled = True

    @staticmethod
    def checksum32(data: bytes) -> int:
        """Calculate 32-bit checksum (little-endian sum)."""
        checksum = 0
        # Process 4 bytes at a time
        for i in range(0, len(data) - 3, 4):
            checksum += struct.unpack_from("<I", data, i)[0]
        return checksum & 0xFFFFFFFF

    @staticmethod
    def validate_image(data: bytes) -> Optional[MainHeader]:
        """
        Validate Marvell boot image.

        Args:
            data: Image data

        Returns:
            MainHeader if valid, None otherwise
        """
        if len(data) < 64:
            log.error("Image too small for header")
            return None

        hdr = MainHeader.from_bytes(data)

        if hdr.magic != MAIN_HDR_MAGIC:
            log.error(f"Invalid header magic: 0x{hdr.magic:08X} (expected 0x{MAIN_HDR_MAGIC:08X})")
            return None

        if hdr.prolog_size < 64:
            log.error("Prolog too small")
            return None

        if hdr.prolog_size > len(data):
            log.error("Prolog larger than image")
            return None

        if hdr.prolog_size > 384 * 1024:
            log.error("Prolog larger than 384KB limit")
            return None

        # Validate prolog checksum
        expected_prolog_csum = Mvebu64Protocol.checksum32(data[:hdr.prolog_size])
        # The checksum field itself is part of the sum, so we need to subtract it
        expected_prolog_csum -= hdr.prolog_checksum
        if expected_prolog_csum != hdr.prolog_checksum:
            log.error("Invalid prolog checksum")
            return None

        if hdr.bl_image_size % 4 != 0:
            log.error("Bootloader size not 4-byte aligned")
            return None

        if hdr.prolog_size + hdr.bl_image_size > len(data):
            log.error("Bootloader larger than image")
            return None

        # Validate bootloader checksum
        bl_data = data[hdr.prolog_size:hdr.prolog_size + hdr.bl_image_size]
        expected_bl_csum = Mvebu64Protocol.checksum32(bl_data)
        if expected_bl_csum != hdr.bl_image_checksum:
            log.error("Invalid bootloader checksum")
            return None

        if hdr.load_addr % 8 != 0:
            log.error("Load address not 8-byte aligned")
            return None

        if hdr.exec_addr % 4 != 0:
            log.error("Exec address not 4-byte aligned")
            return None

        log.info(f"Valid image: prolog={hdr.prolog_size}B, bootloader={hdr.bl_image_size}B")
        return hdr

    @staticmethod
    def align_image(data: bytes, hdr: MainHeader) -> bytes:
        """
        Align prolog to XMODEM block size.

        Args:
            data: Original image data
            hdr: Parsed header

        Returns:
            Aligned image data
        """
        prolog_align = hdr.prolog_size % XMODEM_BLOCK_SIZE
        if prolog_align == 0:
            return data

        log.info("Aligning prolog to XMODEM block size")
        padding = XMODEM_BLOCK_SIZE - prolog_align

        # Create new image with padding after prolog
        aligned = bytearray(len(data) + padding)
        aligned[:hdr.prolog_size] = data[:hdr.prolog_size]
        aligned[hdr.prolog_size:hdr.prolog_size + padding] = b'\x00' * padding
        aligned[hdr.prolog_size + padding:] = data[hdr.prolog_size:]

        # Update prolog size in header
        new_prolog_size = hdr.prolog_size + padding
        struct.pack_into("<I", aligned, 4, new_prolog_size)

        # Recalculate prolog checksum
        new_checksum = Mvebu64Protocol.checksum32(bytes(aligned[:new_prolog_size]))
        # Subtract the checksum field itself (it's at offset 8)
        old_checksum = struct.unpack_from("<I", aligned, 8)[0]
        new_checksum -= old_checksum
        struct.pack_into("<I", aligned, 8, new_checksum)

        return bytes(aligned)

    def _make_xmodem_block(self, data: bytes) -> bytes:
        """
        Create XMODEM block with checksum.

        Args:
            data: Block data (128 bytes, padded if needed)

        Returns:
            Complete block (132 bytes)
        """
        # Pad to block size
        padded = data.ljust(XMODEM_BLOCK_SIZE, b'\x00')

        # Calculate checksum
        checksum = sum(padded) & 0xFF

        # Build block: SOH + seq + ~seq + data + checksum
        block = bytes([SOH, self._seq, 0xFF - self._seq]) + padded + bytes([checksum])
        return block

    async def _send_boot_pattern(
        self,
        progress_callback: Optional[Callable[[Mvebu64Stats], None]] = None,
    ) -> bool:
        """
        Send boot pattern until NAK received.

        Returns:
            True if NAK received (BootROM ready)
        """
        self.stats.state = Mvebu64State.SENDING_PATTERN
        pattern = BOOT_PATTERN_64
        interval_s = self.config.pattern_interval_ms / 1000.0

        log.info("Sending boot pattern (waiting for BootROM NAK)...")

        # Start pattern sending loop
        deadline = time.time() + (self.config.nak_timeout_ms / 1000.0)

        while time.time() < deadline:
            if self._cancelled:
                self.stats.state = Mvebu64State.ERROR
                self.stats.error_message = "Cancelled"
                return False

            # Send burst of patterns
            for _ in range(self.config.pattern_repeat):
                self.write(pattern)

            # Check for NAK
            try:
                data = self.read()
                if data:
                    for byte in data:
                        if byte == NAK:
                            log.info("BootROM NAK received!")
                            self.stats.state = Mvebu64State.SENDING_SYNC
                            return True
            except Exception as e:
                log.debug(f"Read during pattern: {e}")

            self.stats.elapsed_time = time.time() - self._start_time
            if progress_callback:
                progress_callback(self.stats)

            await asyncio.sleep(interval_s)

        self.stats.state = Mvebu64State.ERROR
        self.stats.error_message = "BootROM NAK timeout"
        log.error("Timeout waiting for BootROM NAK")
        return False

    async def _send_sync(self) -> bool:
        """
        Send sync sequence after NAK.

        Returns:
            True if sync sent successfully
        """
        log.debug("Sending sync sequence")
        sync_block = bytes([0xFF] * (XMODEM_BLOCK_SIZE + 4))
        self.write(sync_block)

        # Small delay for BootROM to process
        await asyncio.sleep(0.024)

        # Flush any input
        try:
            self.read()
        except Exception:
            pass

        log.info("BootROM ready for image transfer")
        return True

    async def _xmodem_send_block(
        self,
        block: bytes,
        allow_output: bool = False,
    ) -> bool:
        """
        Send XMODEM block and wait for ACK.

        Args:
            block: Complete XMODEM block
            allow_output: Allow bootrom output on last block

        Returns:
            True if ACK received
        """
        timeout_ms = 10000 if allow_output else self.config.ack_timeout_ms

        for retry in range(self.config.max_retries):
            if self._cancelled:
                return False

            # Wait longer on retries
            if retry >= 7:
                await asyncio.sleep(2.0)

            self.write(block)

            deadline = time.time() + (timeout_ms / 1000.0)

            while time.time() < deadline:
                try:
                    data = self.read()
                    if not data:
                        await asyncio.sleep(0.01)
                        continue

                    for byte in data:
                        if byte == ACK:
                            return True
                        elif byte == NAK:
                            log.debug(f"NAK on block {self._seq}, retry {retry + 1}")
                            self.stats.retries += 1
                            break
                        elif allow_output:
                            # Print BootROM output
                            try:
                                print(chr(byte), end='', flush=True)
                            except Exception:
                                pass
                    else:
                        continue
                    break  # Got NAK, retry
                except Exception as e:
                    log.debug(f"Read error: {e}")
                    await asyncio.sleep(0.01)
            else:
                # Timeout
                log.debug(f"Timeout on block {self._seq}, retry {retry + 1}")
                self.stats.retries += 1

        return False

    async def _xmodem_transfer(
        self,
        data: bytes,
        state: Mvebu64State,
        allow_output_last: bool = False,
        progress_callback: Optional[Callable[[Mvebu64Stats], None]] = None,
    ) -> bool:
        """
        Transfer data via XMODEM.

        Args:
            data: Data to transfer
            state: State to set during transfer
            allow_output_last: Allow output on last block ACK
            progress_callback: Progress callback

        Returns:
            True if transfer successful
        """
        self.stats.state = state
        total_blocks = (len(data) + XMODEM_BLOCK_SIZE - 1) // XMODEM_BLOCK_SIZE
        self.stats.blocks_total = total_blocks

        offset = 0
        while offset < len(data):
            if self._cancelled:
                return False

            chunk = data[offset:offset + XMODEM_BLOCK_SIZE]
            block = self._make_xmodem_block(chunk)
            is_last = (offset + len(chunk) >= len(data))
            allow_output = allow_output_last and is_last

            if not await self._xmodem_send_block(block, allow_output):
                self.stats.state = Mvebu64State.ERROR
                self.stats.error_message = f"Block {self._seq} transfer failed"
                return False

            offset += len(chunk)
            self._seq = (self._seq % 255) + 1
            self.stats.blocks_sent += 1

            # Update per-phase stats
            if state == Mvebu64State.XMODEM_PROLOG:
                self.stats.prolog_bytes = offset
            else:
                self.stats.bootloader_bytes = offset

            self.stats.elapsed_time = time.time() - self._start_time
            if progress_callback:
                progress_callback(self.stats)

        return True

    async def _xmodem_finish(self) -> bool:
        """
        Send EOT and wait for ACK.

        Returns:
            True if EOT acknowledged
        """
        self.stats.state = Mvebu64State.XMODEM_FINISH
        log.debug("Sending EOT...")

        for retry in range(self.config.max_retries):
            if self._cancelled:
                return False

            if retry >= 7:
                await asyncio.sleep(2.0)

            self.write(bytes([EOT]))

            deadline = time.time() + (self.config.ack_timeout_ms / 1000.0)
            while time.time() < deadline:
                try:
                    data = self.read()
                    if data and ACK in data:
                        log.info("EOT acknowledged")
                        return True
                except Exception:
                    pass
                await asyncio.sleep(0.01)

        log.warning("EOT not acknowledged")
        return True  # Data was sent, EOT ack is not critical

    async def boot(
        self,
        image_data: bytes,
        progress_callback: Optional[Callable[[Mvebu64Stats], None]] = None,
    ) -> bool:
        """
        Complete mvebu64boot sequence.

        Args:
            image_data: Boot image data
            progress_callback: Optional progress callback

        Returns:
            True if boot successful
        """
        self._cancelled = False
        self._start_time = time.time()
        self._seq = 1
        self.stats = Mvebu64Stats()

        log.info("Starting mvebu64boot sequence for Armada 7040/8040")

        # Validate image
        hdr = self.validate_image(image_data)
        if not hdr:
            self.stats.state = Mvebu64State.ERROR
            self.stats.error_message = "Invalid image"
            return False

        # Align image if needed
        image_data = self.align_image(image_data, hdr)
        # Re-parse header after alignment
        hdr = MainHeader.from_bytes(image_data)

        self.stats.prolog_total = hdr.prolog_size
        self.stats.bootloader_total = hdr.bl_image_size

        # Send boot pattern
        if not await self._send_boot_pattern(progress_callback):
            return False

        # Send sync sequence
        if not await self._send_sync():
            return False

        # Transfer prolog (allow output on last ACK)
        log.info(f"Sending prolog ({hdr.prolog_size} bytes)...")
        prolog = image_data[:hdr.prolog_size]
        if not await self._xmodem_transfer(
            prolog,
            Mvebu64State.XMODEM_PROLOG,
            allow_output_last=True,
            progress_callback=progress_callback,
        ):
            return False

        # Transfer bootloader
        log.info(f"Sending bootloader ({hdr.bl_image_size} bytes)...")
        bootloader = image_data[hdr.prolog_size:hdr.prolog_size + hdr.bl_image_size]
        if not await self._xmodem_transfer(
            bootloader,
            Mvebu64State.XMODEM_BOOTLOADER,
            allow_output_last=False,
            progress_callback=progress_callback,
        ):
            return False

        # Send EOT
        if not await self._xmodem_finish():
            log.warning("EOT not acknowledged, but transfer may have succeeded")

        self.stats.state = Mvebu64State.COMPLETE
        self.stats.elapsed_time = time.time() - self._start_time

        if progress_callback:
            progress_callback(self.stats)

        log.info(f"Mvebu64boot complete in {self.stats.elapsed_time:.1f}s")
        return True
