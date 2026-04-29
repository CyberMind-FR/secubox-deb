"""
SecuBox Eye Remote — XMODEM Protocol
Standard XMODEM-CRC file transfer for serial boot.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

XMODEM-CRC Protocol:
- 128-byte blocks with CRC-16-CCITT
- Used by Marvell BootROM for receiving boot images
- Supports both standard XMODEM and XMODEM-1K (1024-byte blocks)
"""
from __future__ import annotations

import asyncio
import logging
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import AsyncIterator, Callable, Optional

log = logging.getLogger(__name__)


class XmodemControl(IntEnum):
    """XMODEM control characters."""
    SOH = 0x01  # Start of header (128 byte block)
    STX = 0x02  # Start of header (1024 byte block)
    EOT = 0x04  # End of transmission
    ACK = 0x06  # Acknowledge
    NAK = 0x15  # Negative acknowledge
    CAN = 0x18  # Cancel
    CRC = 0x43  # 'C' - CRC mode request


@dataclass
class XmodemStats:
    """Transfer statistics."""
    total_bytes: int = 0
    bytes_sent: int = 0
    blocks_sent: int = 0
    blocks_total: int = 0
    retries: int = 0
    errors: int = 0

    @property
    def progress(self) -> float:
        """Progress as fraction 0.0-1.0."""
        if self.total_bytes == 0:
            return 0.0
        return min(1.0, self.bytes_sent / self.total_bytes)


class XmodemProtocol:
    """
    XMODEM-CRC file transfer protocol.

    Supports:
    - Standard XMODEM (128-byte blocks)
    - XMODEM-1K (1024-byte blocks)
    - CRC-16-CCITT error detection
    """

    # Protocol constants
    BLOCK_SIZE_STD = 128
    BLOCK_SIZE_1K = 1024
    PAD_BYTE = 0x1A  # Ctrl-Z padding

    # Timing
    TIMEOUT_INIT = 60.0  # Wait for receiver 'C' or NAK
    TIMEOUT_ACK = 10.0   # Wait for ACK/NAK after block
    MAX_RETRIES = 10     # Max retries per block
    MAX_ERRORS = 3       # Max consecutive errors before abort

    def __init__(
        self,
        read_func: Callable[[], bytes],
        write_func: Callable[[bytes], None],
        block_size: int = 128,
    ):
        """
        Initialize XMODEM protocol.

        Args:
            read_func: Function to read bytes from serial (blocking)
            write_func: Function to write bytes to serial
            block_size: Block size (128 or 1024)
        """
        self.read = read_func
        self.write = write_func
        self.block_size = block_size
        self.use_crc = True  # CRC mode (receiver sends 'C')
        self.stats = XmodemStats()
        self._cancelled = False

    def cancel(self) -> None:
        """Cancel ongoing transfer."""
        self._cancelled = True
        # Send cancel sequence
        self.write(bytes([XmodemControl.CAN] * 3))

    def _calc_crc16(self, data: bytes) -> int:
        """Calculate CRC-16-CCITT (XModem variant)."""
        crc = 0
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ 0x1021
                else:
                    crc <<= 1
        return crc & 0xFFFF

    def _calc_checksum(self, data: bytes) -> int:
        """Calculate simple checksum (fallback if receiver doesn't support CRC)."""
        return sum(data) & 0xFF

    def _make_block(self, seq: int, data: bytes) -> bytes:
        """
        Create XMODEM block with header and CRC/checksum.

        Args:
            seq: Block sequence number (1-255, wraps)
            data: Block data (will be padded to block_size)

        Returns:
            Complete block ready to send
        """
        # Determine header byte
        header_byte = XmodemControl.STX if self.block_size == 1024 else XmodemControl.SOH

        # Pad data to block size
        padded = data.ljust(self.block_size, bytes([self.PAD_BYTE]))

        # Build header: SOH/STX + seq + ~seq
        seq_byte = seq & 0xFF
        header = bytes([header_byte, seq_byte, 0xFF - seq_byte])

        # Add error detection
        if self.use_crc:
            crc = self._calc_crc16(padded)
            trailer = struct.pack('>H', crc)  # Big-endian CRC
        else:
            checksum = self._calc_checksum(padded)
            trailer = bytes([checksum])

        return header + padded + trailer

    async def _wait_for_receiver(self) -> bool:
        """
        Wait for receiver to initiate transfer.

        Returns:
            True if receiver ready (sent 'C' for CRC or NAK for checksum)
        """
        log.debug("Waiting for receiver initiation...")
        deadline = asyncio.get_event_loop().time() + self.TIMEOUT_INIT

        while asyncio.get_event_loop().time() < deadline:
            if self._cancelled:
                return False

            try:
                # Non-blocking read attempt
                data = self.read()
                if not data:
                    await asyncio.sleep(0.1)
                    continue

                for byte in data:
                    if byte == XmodemControl.CRC:
                        log.info("Receiver ready (CRC mode)")
                        self.use_crc = True
                        return True
                    elif byte == XmodemControl.NAK:
                        log.info("Receiver ready (checksum mode)")
                        self.use_crc = False
                        return True
                    elif byte == XmodemControl.CAN:
                        log.warning("Receiver cancelled transfer")
                        return False

            except Exception as e:
                log.debug(f"Read error during init: {e}")
                await asyncio.sleep(0.1)

        log.error("Timeout waiting for receiver")
        return False

    async def _send_block(self, block: bytes) -> bool:
        """
        Send a single block and wait for ACK.

        Args:
            block: Complete block to send

        Returns:
            True if ACK received, False otherwise
        """
        retries = 0

        while retries < self.MAX_RETRIES:
            if self._cancelled:
                return False

            self.write(block)

            # Wait for response
            deadline = asyncio.get_event_loop().time() + self.TIMEOUT_ACK

            while asyncio.get_event_loop().time() < deadline:
                try:
                    data = self.read()
                    if not data:
                        await asyncio.sleep(0.01)
                        continue

                    for byte in data:
                        if byte == XmodemControl.ACK:
                            return True
                        elif byte == XmodemControl.NAK:
                            log.debug(f"NAK received, retry {retries + 1}")
                            self.stats.retries += 1
                            retries += 1
                            break
                        elif byte == XmodemControl.CAN:
                            log.warning("Receiver cancelled")
                            return False
                    else:
                        continue
                    break  # Got NAK, retry

                except Exception as e:
                    log.debug(f"Read error: {e}")
                    await asyncio.sleep(0.01)
            else:
                # Timeout waiting for response
                log.debug(f"Timeout waiting for ACK, retry {retries + 1}")
                self.stats.retries += 1
                retries += 1

        self.stats.errors += 1
        return False

    async def send(
        self,
        data: bytes,
        progress_callback: Optional[Callable[[XmodemStats], None]] = None,
    ) -> bool:
        """
        Send data using XMODEM protocol.

        Args:
            data: Data to send
            progress_callback: Optional callback for progress updates

        Returns:
            True if transfer successful
        """
        self._cancelled = False
        self.stats = XmodemStats(
            total_bytes=len(data),
            blocks_total=(len(data) + self.block_size - 1) // self.block_size,
        )

        log.info(f"Starting XMODEM transfer: {len(data)} bytes, {self.stats.blocks_total} blocks")

        # Wait for receiver
        if not await self._wait_for_receiver():
            return False

        # Send blocks
        seq = 1
        offset = 0
        consecutive_errors = 0

        while offset < len(data):
            if self._cancelled:
                log.info("Transfer cancelled")
                return False

            # Extract block data
            chunk = data[offset:offset + self.block_size]
            block = self._make_block(seq, chunk)

            # Send block
            if await self._send_block(block):
                offset += len(chunk)
                self.stats.bytes_sent = offset
                self.stats.blocks_sent += 1
                consecutive_errors = 0

                # Sequence number wraps at 255
                seq = (seq % 255) + 1

                if progress_callback:
                    progress_callback(self.stats)

                log.debug(f"Block {self.stats.blocks_sent}/{self.stats.blocks_total} sent")
            else:
                consecutive_errors += 1
                if consecutive_errors >= self.MAX_ERRORS:
                    log.error(f"Too many consecutive errors ({consecutive_errors})")
                    self.cancel()
                    return False

        # Send EOT
        log.debug("Sending EOT...")
        eot_retries = 0
        while eot_retries < 3:
            self.write(bytes([XmodemControl.EOT]))

            deadline = asyncio.get_event_loop().time() + self.TIMEOUT_ACK
            while asyncio.get_event_loop().time() < deadline:
                try:
                    data = self.read()
                    if data and XmodemControl.ACK in data:
                        log.info(f"XMODEM transfer complete: {self.stats.bytes_sent} bytes")
                        return True
                except Exception:
                    pass
                await asyncio.sleep(0.01)

            eot_retries += 1

        log.warning("EOT not acknowledged, but data was sent")
        return True  # Data was sent, EOT ack is not critical

    async def send_iter(
        self,
        data: bytes,
    ) -> AsyncIterator[XmodemStats]:
        """
        Send data with async iteration for progress.

        Args:
            data: Data to send

        Yields:
            XmodemStats after each block
        """
        self._cancelled = False
        self.stats = XmodemStats(
            total_bytes=len(data),
            blocks_total=(len(data) + self.block_size - 1) // self.block_size,
        )

        # Wait for receiver
        if not await self._wait_for_receiver():
            self.stats.errors += 1
            yield self.stats
            return

        # Send blocks
        seq = 1
        offset = 0
        consecutive_errors = 0

        while offset < len(data):
            if self._cancelled:
                return

            chunk = data[offset:offset + self.block_size]
            block = self._make_block(seq, chunk)

            if await self._send_block(block):
                offset += len(chunk)
                self.stats.bytes_sent = offset
                self.stats.blocks_sent += 1
                consecutive_errors = 0
                seq = (seq % 255) + 1
                yield self.stats
            else:
                consecutive_errors += 1
                if consecutive_errors >= self.MAX_ERRORS:
                    self.stats.errors += 1
                    yield self.stats
                    return

        # Send EOT (simplified, don't wait for ack in iterator)
        self.write(bytes([XmodemControl.EOT]))
        yield self.stats
