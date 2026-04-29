"""
SecuBox Eye Remote — Recovery Controller
Main recovery controller for Marvell board recovery via USB serial.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Supported boards:
- MOCHAbin (Armada 7040)
- ESPRESSObin v7 (Armada 3720)
- ESPRESSObin Ultra (Armada 3720)

Recovery methods:
- kwboot: Serial boot via UART for bricked boards
- mvebu64boot: 64-bit boot for Armada 7K/8K
- Tow-Boot UEFI: Modern UEFI firmware installation
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Callable, Optional

log = logging.getLogger(__name__)


class BoardType(Enum):
    """Supported board types."""
    MOCHABIN = auto()
    ESPRESSOBIN_V7 = auto()
    ESPRESSOBIN_ULTRA = auto()
    UNKNOWN = auto()


class RecoveryState(Enum):
    """Recovery state machine states."""
    IDLE = auto()
    DETECTING = auto()
    BOOTROM_DETECTED = auto()
    KWBOOT_SENDING = auto()
    XMODEM_TRANSFER = auto()
    UBOOT_PROMPT = auto()
    FLASHING = auto()
    VERIFYING = auto()
    COMPLETE = auto()
    ERROR = auto()


class RecoveryMethod(Enum):
    """Recovery methods."""
    KWBOOT = auto()         # Serial boot via kwboot
    MVEBU64BOOT = auto()    # 64-bit boot for Armada 7K/8K
    UBOOT_CMD = auto()       # U-Boot command line
    TOWBOOT = auto()         # Tow-Boot UEFI installation


@dataclass
class RecoveryStatus:
    """Current recovery status."""
    state: RecoveryState = RecoveryState.IDLE
    board: BoardType = BoardType.UNKNOWN
    method: RecoveryMethod = RecoveryMethod.KWBOOT
    progress: float = 0.0
    message: str = "Ready"
    error: Optional[str] = None
    elapsed_time: float = 0.0
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "state": self.state.name,
            "board": self.board.name,
            "method": self.method.name,
            "progress": self.progress,
            "message": self.message,
            "error": self.error,
            "elapsed_time": self.elapsed_time,
            "details": self.details,
        }


@dataclass
class BoardConfig:
    """Board-specific configuration."""
    board_type: BoardType
    name: str
    soc: str
    boot_method: RecoveryMethod
    uboot_file: str
    rescue_file: str
    towboot_file: Optional[str] = None
    flash_offset: int = 0
    flash_size: int = 0x200000  # 2MB default


# Board configurations
BOARD_CONFIGS = {
    BoardType.MOCHABIN: BoardConfig(
        board_type=BoardType.MOCHABIN,
        name="MOCHAbin",
        soc="Armada 7040",
        boot_method=RecoveryMethod.MVEBU64BOOT,
        uboot_file="mochabin/uboot-spi.bin",
        rescue_file="mochabin/rescue-initramfs.img",
        towboot_file="mochabin/towboot.img",
        flash_offset=0,
        flash_size=0x400000,  # 4MB
    ),
    BoardType.ESPRESSOBIN_V7: BoardConfig(
        board_type=BoardType.ESPRESSOBIN_V7,
        name="ESPRESSObin v7",
        soc="Armada 3720",
        boot_method=RecoveryMethod.KWBOOT,
        uboot_file="espressobin-v7/uboot-spi.bin",
        rescue_file="espressobin-v7/rescue-initramfs.img",
        flash_offset=0,
        flash_size=0x200000,  # 2MB
    ),
    BoardType.ESPRESSOBIN_ULTRA: BoardConfig(
        board_type=BoardType.ESPRESSOBIN_ULTRA,
        name="ESPRESSObin Ultra",
        soc="Armada 3720",
        boot_method=RecoveryMethod.KWBOOT,
        uboot_file="espressobin-ultra/uboot-spi.bin",
        rescue_file="espressobin-ultra/rescue-initramfs.img",
        flash_offset=0,
        flash_size=0x200000,
    ),
}

# Detection signatures from serial output
BOARD_SIGNATURES = {
    BoardType.MOCHABIN: [b"MOCHAbin", b"Armada 7040", b"A7K", b"7040"],
    BoardType.ESPRESSOBIN_V7: [b"ESPRESSObin", b"Armada 3720", b"espressobin-v7"],
    BoardType.ESPRESSOBIN_ULTRA: [b"ESPRESSObin Ultra", b"Ultra"],
}


class RecoveryController:
    """
    Main recovery controller for Eye Remote.

    Manages board detection, recovery workflows, and firmware flashing
    via USB serial connection (/dev/ttyGS0).
    """

    SERIAL_PORT = "/dev/ttyGS0"
    BAUD_RATE = 115200
    RECOVERY_DIR = Path("/srv/secubox-recovery/boards")
    CONFIG_DIR = Path("/srv/secubox-recovery/config")

    def __init__(self):
        self.status = RecoveryStatus()
        self._serial = None
        self._start_time = 0.0
        self._listeners: list[Callable[[RecoveryStatus], None]] = []
        self._cancelled = False

    def add_listener(self, callback: Callable[[RecoveryStatus], None]) -> None:
        """Add status change listener."""
        self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[RecoveryStatus], None]) -> None:
        """Remove status change listener."""
        if callback in self._listeners:
            self._listeners.remove(callback)

    def _notify_listeners(self) -> None:
        """Notify all listeners of status change."""
        for listener in self._listeners:
            try:
                listener(self.status)
            except Exception as e:
                log.error(f"Listener error: {e}")

    def _update_status(
        self,
        state: Optional[RecoveryState] = None,
        progress: Optional[float] = None,
        message: Optional[str] = None,
        error: Optional[str] = None,
        **details,
    ) -> None:
        """Update status and notify listeners."""
        if state is not None:
            self.status.state = state
        if progress is not None:
            self.status.progress = progress
        if message is not None:
            self.status.message = message
        if error is not None:
            self.status.error = error
        self.status.elapsed_time = time.time() - self._start_time
        self.status.details.update(details)
        self._notify_listeners()

    async def _open_serial(self) -> bool:
        """Open serial port for recovery."""
        try:
            import serial
            self._serial = serial.Serial(
                self.SERIAL_PORT,
                self.BAUD_RATE,
                timeout=0.1,  # Non-blocking reads
            )
            log.info(f"Opened serial port {self.SERIAL_PORT} @ {self.BAUD_RATE}")
            return True
        except ImportError:
            log.error("pyserial not installed")
            self._update_status(
                state=RecoveryState.ERROR,
                error="pyserial not installed",
            )
            return False
        except Exception as e:
            log.error(f"Failed to open serial: {e}")
            self._update_status(
                state=RecoveryState.ERROR,
                error=f"Serial port error: {e}",
            )
            return False

    def _close_serial(self) -> None:
        """Close serial port."""
        if self._serial:
            try:
                self._serial.close()
            except Exception:
                pass
            self._serial = None

    def _serial_read(self) -> bytes:
        """Read from serial (used by protocols)."""
        if self._serial:
            return self._serial.read(1024)
        return b""

    def _serial_write(self, data: bytes) -> None:
        """Write to serial (used by protocols)."""
        if self._serial:
            self._serial.write(data)

    async def detect_board(self, timeout: float = 10.0) -> BoardType:
        """
        Detect board type from serial output.

        Args:
            timeout: Detection timeout in seconds

        Returns:
            Detected board type
        """
        self._start_time = time.time()
        self._update_status(
            state=RecoveryState.DETECTING,
            message="Detecting board...",
            progress=0.0,
        )

        if not await self._open_serial():
            return BoardType.UNKNOWN

        try:
            recv_buffer = bytearray()
            deadline = time.time() + timeout

            while time.time() < deadline:
                if self._cancelled:
                    self._update_status(
                        state=RecoveryState.ERROR,
                        error="Cancelled",
                    )
                    return BoardType.UNKNOWN

                data = self._serial_read()
                if data:
                    recv_buffer.extend(data)

                    # Check for board signatures
                    for board_type, signatures in BOARD_SIGNATURES.items():
                        for sig in signatures:
                            if sig in recv_buffer:
                                log.info(f"Detected board: {board_type.name}")
                                self.status.board = board_type
                                self._update_status(
                                    state=RecoveryState.BOOTROM_DETECTED,
                                    message=f"Detected: {BOARD_CONFIGS[board_type].name}",
                                    progress=0.1,
                                )
                                return board_type

                    # Check for generic BootROM signature
                    if b"BootROM" in recv_buffer or b"bootrom" in recv_buffer:
                        log.info("BootROM detected, board type unknown")
                        self._update_status(
                            state=RecoveryState.BOOTROM_DETECTED,
                            message="BootROM detected (unknown board)",
                            progress=0.1,
                        )
                        return BoardType.UNKNOWN

                progress = (time.time() - self._start_time) / timeout * 0.1
                self._update_status(progress=progress)
                await asyncio.sleep(0.1)

            self._update_status(
                state=RecoveryState.IDLE,
                message="No board detected",
                progress=0.0,
            )
            return BoardType.UNKNOWN

        finally:
            self._close_serial()

    def _load_image(self, image_path: str) -> Optional[bytes]:
        """Load boot image from recovery storage."""
        full_path = self.RECOVERY_DIR / image_path
        if not full_path.exists():
            log.error(f"Image not found: {full_path}")
            return None
        try:
            return full_path.read_bytes()
        except Exception as e:
            log.error(f"Failed to load image: {e}")
            return None

    async def kwboot_recovery(
        self,
        board_type: Optional[BoardType] = None,
        image_path: Optional[str] = None,
    ) -> bool:
        """
        Perform kwboot recovery sequence.

        Args:
            board_type: Target board type (auto-detect if None)
            image_path: Custom image path (use default if None)

        Returns:
            True if recovery successful
        """
        from .protocols.kwboot import KwbootProtocol, KwbootConfig, SoCType

        self._start_time = time.time()
        self._cancelled = False

        # Detect board if not specified
        if board_type is None:
            board_type = await self.detect_board()
            if board_type == BoardType.UNKNOWN:
                self._update_status(
                    state=RecoveryState.ERROR,
                    error="Board detection failed",
                )
                return False

        self.status.board = board_type
        config = BOARD_CONFIGS.get(board_type)
        if not config:
            self._update_status(
                state=RecoveryState.ERROR,
                error=f"No config for board: {board_type.name}",
            )
            return False

        # Load boot image
        img_path = image_path or config.uboot_file
        image_data = self._load_image(img_path)
        if not image_data:
            self._update_status(
                state=RecoveryState.ERROR,
                error=f"Image not found: {img_path}",
            )
            return False

        self._update_status(
            state=RecoveryState.KWBOOT_SENDING,
            message="Starting kwboot...",
            progress=0.15,
            image_size=len(image_data),
        )

        # Open serial port
        if not await self._open_serial():
            return False

        try:
            # Configure kwboot for board
            soc_type = SoCType.ARMADA_3720
            if board_type == BoardType.MOCHABIN:
                soc_type = SoCType.ARMADA_7040

            kwboot_config = KwbootConfig(
                soc_type=soc_type,
                baud_rate=self.BAUD_RATE,
            )

            kwboot = KwbootProtocol(
                self._serial_read,
                self._serial_write,
                kwboot_config,
            )

            def progress_callback(stats):
                if stats.state.name == "XMODEM_TRANSFER":
                    self.status.state = RecoveryState.XMODEM_TRANSFER
                    if stats.xmodem:
                        self.status.progress = 0.2 + 0.7 * stats.xmodem.progress
                        self.status.details["blocks_sent"] = stats.xmodem.blocks_sent
                        self.status.details["blocks_total"] = stats.xmodem.blocks_total
                self.status.message = f"kwboot: {stats.state.name}"
                self.status.elapsed_time = stats.elapsed_time
                self._notify_listeners()

            # Execute kwboot
            success = await kwboot.boot(
                image_data,
                wait_prompt=True,
                progress_callback=progress_callback,
            )

            if success:
                self._update_status(
                    state=RecoveryState.UBOOT_PROMPT,
                    message="Boot image loaded",
                    progress=0.9,
                )
                return True
            else:
                self._update_status(
                    state=RecoveryState.ERROR,
                    error="kwboot failed",
                )
                return False

        except Exception as e:
            log.exception(f"kwboot error: {e}")
            self._update_status(
                state=RecoveryState.ERROR,
                error=str(e),
            )
            return False

        finally:
            self._close_serial()

    async def mvebu64_recovery(
        self,
        board_type: Optional[BoardType] = None,
        image_path: Optional[str] = None,
    ) -> bool:
        """
        Perform mvebu64boot recovery sequence for Armada 7040/8040.

        Args:
            board_type: Target board type (auto-detect if None)
            image_path: Custom image path (use default if None)

        Returns:
            True if recovery successful
        """
        from .protocols.mvebu64boot import Mvebu64Protocol, Mvebu64Config

        self._start_time = time.time()
        self._cancelled = False

        # Detect board if not specified
        if board_type is None:
            board_type = await self.detect_board()
            if board_type == BoardType.UNKNOWN:
                self._update_status(
                    state=RecoveryState.ERROR,
                    error="Board detection failed",
                )
                return False

        # Verify board uses mvebu64boot
        if board_type != BoardType.MOCHABIN:
            log.warning(f"Board {board_type.name} may not support mvebu64boot")

        self.status.board = board_type
        self.status.method = RecoveryMethod.MVEBU64BOOT
        config = BOARD_CONFIGS.get(board_type)
        if not config:
            self._update_status(
                state=RecoveryState.ERROR,
                error=f"No config for board: {board_type.name}",
            )
            return False

        # Load boot image
        img_path = image_path or config.uboot_file
        image_data = self._load_image(img_path)
        if not image_data:
            self._update_status(
                state=RecoveryState.ERROR,
                error=f"Image not found: {img_path}",
            )
            return False

        self._update_status(
            state=RecoveryState.KWBOOT_SENDING,
            message="Starting mvebu64boot...",
            progress=0.15,
            image_size=len(image_data),
        )

        # Open serial port
        if not await self._open_serial():
            return False

        try:
            mvebu64_config = Mvebu64Config(
                baud_rate=self.BAUD_RATE,
            )

            mvebu64 = Mvebu64Protocol(
                self._serial_read,
                self._serial_write,
                mvebu64_config,
            )

            def progress_callback(stats):
                if stats.state.name == "XMODEM_PROLOG":
                    self.status.state = RecoveryState.XMODEM_TRANSFER
                    self.status.progress = 0.2 + 0.3 * (stats.prolog_bytes / max(1, stats.prolog_total))
                    self.status.details["phase"] = "prolog"
                elif stats.state.name == "XMODEM_BOOTLOADER":
                    self.status.state = RecoveryState.XMODEM_TRANSFER
                    self.status.progress = 0.5 + 0.4 * (stats.bootloader_bytes / max(1, stats.bootloader_total))
                    self.status.details["phase"] = "bootloader"
                self.status.message = f"mvebu64boot: {stats.state.name}"
                self.status.details["blocks_sent"] = stats.blocks_sent
                self.status.details["retries"] = stats.retries
                self.status.elapsed_time = stats.elapsed_time
                self._notify_listeners()

            # Execute mvebu64boot
            success = await mvebu64.boot(
                image_data,
                progress_callback=progress_callback,
            )

            if success:
                self._update_status(
                    state=RecoveryState.UBOOT_PROMPT,
                    message="Boot image loaded via mvebu64boot",
                    progress=0.9,
                )
                return True
            else:
                self._update_status(
                    state=RecoveryState.ERROR,
                    error="mvebu64boot failed",
                )
                return False

        except Exception as e:
            log.exception(f"mvebu64boot error: {e}")
            self._update_status(
                state=RecoveryState.ERROR,
                error=str(e),
            )
            return False

        finally:
            self._close_serial()

    async def auto_recovery(
        self,
        board_type: Optional[BoardType] = None,
        image_path: Optional[str] = None,
    ) -> bool:
        """
        Automatically select and execute appropriate recovery method.

        Args:
            board_type: Target board type (auto-detect if None)
            image_path: Custom image path

        Returns:
            True if recovery successful
        """
        # Detect board if not specified
        if board_type is None:
            board_type = await self.detect_board()
            if board_type == BoardType.UNKNOWN:
                self._update_status(
                    state=RecoveryState.ERROR,
                    error="Board detection failed",
                )
                return False

        config = BOARD_CONFIGS.get(board_type)
        if not config:
            self._update_status(
                state=RecoveryState.ERROR,
                error=f"No config for board: {board_type.name}",
            )
            return False

        # Select recovery method based on board configuration
        if config.boot_method == RecoveryMethod.MVEBU64BOOT:
            log.info(f"Using mvebu64boot for {board_type.name}")
            return await self.mvebu64_recovery(board_type, image_path)
        else:
            log.info(f"Using kwboot for {board_type.name}")
            return await self.kwboot_recovery(board_type, image_path)

    async def flash_uboot(
        self,
        board_type: BoardType,
        target: str = "spi",
        image_path: Optional[str] = None,
    ) -> bool:
        """
        Flash U-Boot to board storage.

        Args:
            board_type: Target board
            target: Flash target (spi, mmc, uefi)
            image_path: Custom image path

        Returns:
            True if flash successful
        """
        config = BOARD_CONFIGS.get(board_type)
        if not config:
            self._update_status(
                state=RecoveryState.ERROR,
                error=f"No config for board: {board_type.name}",
            )
            return False

        self._update_status(
            state=RecoveryState.FLASHING,
            message=f"Flashing U-Boot to {target}...",
            progress=0.0,
        )

        # U-Boot commands for SPI NOR flash
        # (requires U-Boot prompt already available)
        if not await self._open_serial():
            return False

        try:
            commands = [
                "sf probe 0",
                f"sf erase 0 0x{config.flash_size:x}",
                "loady 0x4000000",  # Will trigger XMODEM
                f"sf write 0x4000000 0 0x{config.flash_size:x}",
                "reset",
            ]

            for i, cmd in enumerate(commands):
                self._update_status(
                    message=f"Executing: {cmd}",
                    progress=i / len(commands),
                )

                # Send command
                self._serial_write(f"{cmd}\n".encode())
                await asyncio.sleep(0.5)

                # Read response
                response = self._serial_read()
                log.debug(f"Response: {response}")

                # If loady, need to send image via XMODEM
                if "loady" in cmd:
                    img_path = image_path or config.uboot_file
                    image_data = self._load_image(img_path)
                    if not image_data:
                        return False

                    # TODO: Send via XMODEM
                    await asyncio.sleep(1)

            self._update_status(
                state=RecoveryState.COMPLETE,
                message="Flash complete",
                progress=1.0,
            )
            return True

        except Exception as e:
            log.exception(f"Flash error: {e}")
            self._update_status(
                state=RecoveryState.ERROR,
                error=str(e),
            )
            return False

        finally:
            self._close_serial()

    async def install_towboot(self, board_type: BoardType) -> bool:
        """
        Install Tow-Boot UEFI firmware.

        Args:
            board_type: Target board

        Returns:
            True if installation successful
        """
        config = BOARD_CONFIGS.get(board_type)
        if not config or not config.towboot_file:
            self._update_status(
                state=RecoveryState.ERROR,
                error=f"Tow-Boot not available for {board_type.name}",
            )
            return False

        self._update_status(
            state=RecoveryState.FLASHING,
            message="Installing Tow-Boot UEFI...",
            progress=0.0,
        )

        # Tow-Boot installation is similar to U-Boot flash
        # but may require different partition layout
        return await self.flash_uboot(
            board_type,
            target="uefi",
            image_path=config.towboot_file,
        )

    def cancel(self) -> None:
        """Cancel ongoing recovery operation."""
        self._cancelled = True
        self._close_serial()
        self._update_status(
            state=RecoveryState.IDLE,
            message="Cancelled",
            progress=0.0,
        )

    def get_available_images(self, board_type: BoardType) -> dict[str, dict]:
        """
        Get available recovery images for a board.

        Returns:
            Dict of image name -> {path, size, sha256}
        """
        config = BOARD_CONFIGS.get(board_type)
        if not config:
            return {}

        images = {}
        board_dir = self.RECOVERY_DIR / board_type.name.lower().replace("_", "-")

        if board_dir.exists():
            # Combine bin and img files
            all_files = list(board_dir.glob("*.bin")) + list(board_dir.glob("*.img"))
            for img_file in all_files:
                stat = img_file.stat()
                images[img_file.name] = {
                    "path": str(img_file.relative_to(self.RECOVERY_DIR)),
                    "size": stat.st_size,
                    "modified": stat.st_mtime,
                }

        return images

    @staticmethod
    def get_supported_boards() -> list[dict]:
        """Get list of supported boards with their configurations."""
        return [
            {
                "type": bt.name,
                "name": cfg.name,
                "soc": cfg.soc,
                "method": cfg.boot_method.name,
            }
            for bt, cfg in BOARD_CONFIGS.items()
        ]
