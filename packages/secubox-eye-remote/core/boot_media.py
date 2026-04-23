"""
SecuBox Eye Remote — Boot Media Manager
Manages USB Mass Storage LUN images with 4R double-buffer pattern.

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
from pathlib import Path
from threading import RLock
from typing import BinaryIO, Optional

from models.boot_media import BootImage, BootMediaState

log = logging.getLogger(__name__)

DEFAULT_BOOT_MEDIA_DIR = Path("/var/lib/secubox/eye-remote/boot-media")
GADGET_SETUP_SCRIPT = "/usr/local/bin/gadget-setup.sh"

# Image size limits
MIN_IMAGE_SIZE = 16 * 1024 * 1024  # 16 MiB
MAX_IMAGE_SIZE = 4 * 1024 * 1024 * 1024  # 4 GiB

# Skip TFTP extraction in test mode (set by tests)
SKIP_TFTP_EXTRACTION = os.getenv("SECUBOX_TEST_MODE", "") == "1"


class BootMediaManager:
    """
    Manages boot media images for USB Mass Storage gadget.

    Thread-safe implementation with file-based locking.
    Implements 4R double-buffer pattern (active/shadow).
    """

    def __init__(self, base_dir: Path = DEFAULT_BOOT_MEDIA_DIR):
        self.base_dir = base_dir
        self.images_dir = base_dir / "images"
        self.tftp_dir = base_dir / "tftp"
        self.state_file = base_dir / "state.json"
        self.lock_file = base_dir / ".lock"

        self.active_link = base_dir / "active"
        self.shadow_link = base_dir / "shadow"

        self._lock = RLock()  # Reentrant lock for nested calls

        # Ensure directory structure exists
        self._init_dirs()

    def _init_dirs(self):
        """Initialize directory structure."""
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.images_dir.mkdir(exist_ok=True)
        self.tftp_dir.mkdir(exist_ok=True)

    def _acquire_file_lock(self):
        """
        Acquire file lock for cross-process safety.

        Uses flock-style locking via a lockfile.
        """
        # For now, rely on in-process lock + atomic operations
        # Production should use fcntl.flock() or similar
        pass

    def _release_file_lock(self):
        """Release file lock."""
        pass

    def _load_state(self) -> dict:
        """Load state from state.json."""
        if not self.state_file.exists():
            return {}

        try:
            with open(self.state_file) as f:
                return json.load(f)
        except Exception as e:
            log.error("Failed to load state: %s", e)
            return {}

    def _save_state(self, state_data: dict):
        """Save state to state.json."""
        try:
            with open(self.state_file, 'w') as f:
                json.dump(state_data, f, indent=2, default=str)
        except Exception as e:
            log.error("Failed to save state: %s", e)
            raise

    def _resolve_symlink_image(self, symlink: Path) -> Optional[BootImage]:
        """
        Resolve a symlink to its BootImage metadata.

        Returns None if symlink doesn't exist or is broken.
        """
        if not symlink.exists() or not symlink.is_symlink():
            return None

        try:
            target = symlink.resolve()
            if not target.exists():
                return None

            # Load from state to get metadata
            state_data = self._load_state()

            # Try both active and shadow
            for slot_key in ["active", "shadow"]:
                slot_data = state_data.get(slot_key)
                if slot_data and slot_data.get("path"):
                    img_path = self.images_dir / slot_data["path"]
                    if img_path == target:
                        return BootImage(**slot_data)

            # If not in state, construct minimal metadata
            return BootImage(
                path=target.name,
                sha256="",
                size_bytes=target.stat().st_size,
                created_at=datetime.fromtimestamp(target.stat().st_mtime, tz=timezone.utc),
                label=None
            )

        except Exception as e:
            log.error("Failed to resolve symlink %s: %s", symlink, e)
            return None

    def validate_image(self, path: Path) -> bool:
        """
        Validate boot image format and size.

        Checks for:
        - Size between 16 MiB and 4 GiB
        - FAT32 magic (0x55AA at bytes 510-511, "FAT" in bytes 82-89)
        - OR ext magic (0x53ef at offset 0x438)

        Returns:
            True if valid, False otherwise
        """
        try:
            stat = path.stat()
            size = stat.st_size

            # Check size constraints
            if size < MIN_IMAGE_SIZE or size > MAX_IMAGE_SIZE:
                log.warning("Image size %d out of range [%d, %d]", size, MIN_IMAGE_SIZE, MAX_IMAGE_SIZE)
                return False

            # Read magic bytes
            with open(path, 'rb') as f:
                # Check FAT32 boot signature
                f.seek(510)
                boot_sig = f.read(2)
                if boot_sig == b'\x55\xAA':
                    # Verify FAT string
                    f.seek(82)
                    fat_str = f.read(8)
                    if b"FAT" in fat_str:
                        log.info("Valid FAT32 image detected")
                        return True

                # Check ext magic
                f.seek(0x438)
                ext_magic = f.read(2)
                if ext_magic == b'\x53\xef':
                    log.info("Valid ext filesystem image detected")
                    return True

            log.warning("No valid FAT32 or ext magic found in image")
            return False

        except Exception as e:
            log.error("Failed to validate image %s: %s", path, e)
            return False

    def upload_to_shadow(self, fileobj: BinaryIO, label: Optional[str] = None) -> BootImage:
        """
        Upload boot image to shadow slot.

        Process:
        1. Stream to temporary file
        2. Compute SHA256
        3. Validate image format
        4. Atomic rename to images/
        5. Update shadow symlink
        6. Extract boot files to tftp/ (if applicable)

        Args:
            fileobj: File-like object containing image data
            label: Optional user-friendly label

        Returns:
            BootImage metadata

        Raises:
            ValueError: If image is invalid
        """
        with self._lock:
            self._acquire_file_lock()
            try:
                # Create temporary file
                with tempfile.NamedTemporaryFile(delete=False, dir=self.images_dir, prefix="upload_") as tmp:
                    tmp_path = Path(tmp.name)

                    # Stream data while computing hash
                    hasher = hashlib.sha256()
                    total_bytes = 0

                    chunk_size = 1024 * 1024  # 1 MiB chunks
                    while True:
                        chunk = fileobj.read(chunk_size)
                        if not chunk:
                            break
                        hasher.update(chunk)
                        tmp.write(chunk)
                        total_bytes += len(chunk)

                sha256_hash = hasher.hexdigest()

                # Validate image
                if not self.validate_image(tmp_path):
                    tmp_path.unlink()
                    raise ValueError("Invalid boot image format or size")

                # Generate final filename
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                final_name = f"boot_{timestamp}_{sha256_hash[:8]}.img"
                final_path = self.images_dir / final_name

                # Atomic rename
                tmp_path.rename(final_path)

                log.info("Uploaded boot image: %s (%d bytes, sha256=%s)", final_name, total_bytes, sha256_hash)

                # Create BootImage metadata
                boot_image = BootImage(
                    path=final_name,
                    sha256=sha256_hash,
                    size_bytes=total_bytes,
                    created_at=datetime.now(timezone.utc),
                    label=label
                )

                # Update shadow symlink
                shadow_tmp = self.shadow_link.with_suffix('.tmp')
                if shadow_tmp.exists():
                    shadow_tmp.unlink()

                shadow_tmp.symlink_to(final_path)
                shadow_tmp.rename(self.shadow_link)

                # Update state
                state_data = self._load_state()
                state_data["shadow"] = boot_image.dict()
                self._save_state(state_data)

                # Extract boot files to TFTP (background task, don't block)
                # Skip if in test mode (no root/loop devices)
                if not SKIP_TFTP_EXTRACTION:
                    try:
                        self._extract_boot_files_to_tftp(final_path)
                    except Exception as e:
                        log.warning("Failed to extract boot files to TFTP: %s", e)

                return boot_image

            finally:
                self._release_file_lock()

    def _extract_boot_files_to_tftp(self, image_path: Path):
        """
        Extract boot files from image to tftp/ directory.

        Mounts image (loop device), copies kernel (Image, zImage, vmlinuz),
        device trees (*.dtb), and initrd files to tftp/.

        This is a best-effort operation - failures are logged but not raised.
        """
        try:
            with tempfile.TemporaryDirectory() as mount_point:
                mount_path = Path(mount_point)

                # Try to mount (requires root/loop device support)
                result = subprocess.run(
                    ["mount", "-o", "loop,ro", str(image_path), str(mount_path)],
                    capture_output=True,
                    check=False
                )

                if result.returncode != 0:
                    log.warning("Could not mount image for TFTP extraction (may need root)")
                    return

                try:
                    # Look for boot files
                    boot_patterns = [
                        "Image", "zImage", "vmlinuz*",  # Kernel
                        "*.dtb",  # Device trees
                        "initrd*", "initramfs*"  # Initrd
                    ]

                    for pattern in boot_patterns:
                        for src_file in mount_path.rglob(pattern):
                            if src_file.is_file():
                                dest_file = self.tftp_dir / src_file.name
                                shutil.copy2(src_file, dest_file)
                                log.info("Extracted to TFTP: %s", src_file.name)

                finally:
                    # Unmount
                    subprocess.run(["umount", str(mount_path)], check=False)

        except Exception as e:
            log.warning("TFTP extraction failed: %s", e)

    def swap(self) -> BootMediaState:
        """
        Swap active and shadow slots atomically.

        Process:
        1. Verify shadow slot is not empty
        2. Lock
        3. Eject LUN (detach from USB gadget)
        4. Atomically swap symlinks
        5. Reattach LUN
        6. Update state
        7. Unlock

        Returns:
            Updated BootMediaState

        Raises:
            ValueError: If shadow slot is empty
        """
        with self._lock:
            self._acquire_file_lock()
            try:
                # Verify shadow exists
                if not self.shadow_link.exists():
                    raise ValueError("Shadow slot is empty - cannot swap")

                shadow_target = self.shadow_link.resolve()
                active_target = self.active_link.resolve() if self.active_link.exists() else None

                log.info("Swapping: active=%s <-> shadow=%s", active_target, shadow_target)

                # Eject LUN
                try:
                    subprocess.run(
                        [GADGET_SETUP_SCRIPT, "swap-lun", ""],
                        check=True,
                        capture_output=True
                    )
                except subprocess.CalledProcessError as e:
                    log.error("Failed to eject LUN: %s", e.stderr)
                    raise

                # Atomic swap of symlinks
                # Swap active <- shadow
                active_tmp = self.active_link.with_suffix('.tmp')
                if active_tmp.exists():
                    active_tmp.unlink()
                active_tmp.symlink_to(shadow_target)
                active_tmp.rename(self.active_link)

                # Swap shadow <- old active (or remove if none)
                shadow_tmp = self.shadow_link.with_suffix('.tmp')
                if shadow_tmp.exists():
                    shadow_tmp.unlink()

                if active_target:
                    shadow_tmp.symlink_to(active_target)
                    shadow_tmp.rename(self.shadow_link)
                else:
                    # No previous active, remove shadow
                    if self.shadow_link.exists():
                        self.shadow_link.unlink()

                # Reattach LUN with new active
                try:
                    subprocess.run(
                        [GADGET_SETUP_SCRIPT, "swap-lun", str(self.active_link.resolve())],
                        check=True,
                        capture_output=True
                    )
                except subprocess.CalledProcessError as e:
                    log.error("Failed to reattach LUN: %s", e.stderr)
                    raise

                # Update state
                state_data = self._load_state()

                # Move shadow to active
                new_active = state_data.pop("shadow", None)
                old_active = state_data.get("active")

                state_data["active"] = new_active
                state_data["shadow"] = old_active
                state_data["last_swap_at"] = datetime.now(timezone.utc).isoformat()
                state_data["lun_attached"] = True

                self._save_state(state_data)

                log.info("Swap completed successfully")

                return self.get_state()

            finally:
                self._release_file_lock()

    def rollback(self) -> BootMediaState:
        """
        Rollback to previous boot image.

        This is effectively a swap operation - exchanges active and shadow.

        Returns:
            Updated BootMediaState

        Raises:
            ValueError: If shadow is empty (nothing to rollback to)
        """
        with self._lock:
            if not self.shadow_link.exists():
                raise ValueError("Nothing to rollback to - shadow slot is empty")

            log.info("Rolling back to previous boot image")
            return self.swap()

    def get_state(self) -> BootMediaState:
        """
        Get current boot media state.

        Reads state from state.json and verifies symlinks exist.

        Returns:
            Current BootMediaState
        """
        with self._lock:
            state_data = self._load_state()

            # Resolve active and shadow from symlinks
            active_img = self._resolve_symlink_image(self.active_link)
            shadow_img = self._resolve_symlink_image(self.shadow_link)

            # Check LUN attachment status
            lun_attached = state_data.get("lun_attached", False)

            # Parse last_swap_at
            last_swap_str = state_data.get("last_swap_at")
            last_swap_at = None
            if last_swap_str:
                try:
                    last_swap_at = datetime.fromisoformat(last_swap_str)
                except Exception:
                    pass

            # Check if TFTP has files
            tftp_armed = any(self.tftp_dir.iterdir()) if self.tftp_dir.exists() else False

            return BootMediaState(
                active=active_img,
                shadow=shadow_img,
                lun_attached=lun_attached,
                last_swap_at=last_swap_at,
                tftp_armed=tftp_armed
            )


# Singleton instance
_manager: Optional[BootMediaManager] = None


def get_boot_media_manager() -> BootMediaManager:
    """Get the global boot media manager instance."""
    global _manager
    if _manager is None:
        _manager = BootMediaManager()
    return _manager
