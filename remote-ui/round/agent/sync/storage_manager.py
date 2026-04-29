#!/usr/bin/env python3
"""
SecuBox Eye Remote - Storage Manager

Manages the USB mass storage partition for config sync and backups.
Handles mounting, directory structure, and storage operations.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import os
import shutil
import subprocess
import json
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any


# Storage paths
STORAGE_IMAGE = Path("/srv/eye-remote/storage.img")
STORAGE_MOUNT = Path("/srv/eye-remote/storage")
STORAGE_SIZE_MB = 64  # Default storage size

# Directory structure
STORAGE_DIRS = [
    "configs/secubox",
    "configs/wireguard",
    "configs/credentials",
    "backups",
    "firmware",
    "logs/audit",
]


@dataclass
class StorageInfo:
    """Information about the storage partition."""
    image_path: str
    mount_path: str
    mounted: bool
    size_bytes: int
    used_bytes: int
    free_bytes: int
    filesystem: str = "vfat"

    @property
    def size_mb(self) -> float:
        return self.size_bytes / (1024 * 1024)

    @property
    def used_mb(self) -> float:
        return self.used_bytes / (1024 * 1024)

    @property
    def free_mb(self) -> float:
        return self.free_bytes / (1024 * 1024)

    @property
    def used_percent(self) -> float:
        if self.size_bytes == 0:
            return 0.0
        return (self.used_bytes / self.size_bytes) * 100


@dataclass
class FileInfo:
    """Information about a file in storage."""
    path: str
    name: str
    size: int
    modified: datetime
    is_dir: bool
    encrypted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "name": self.name,
            "size": self.size,
            "modified": self.modified.isoformat(),
            "is_dir": self.is_dir,
            "encrypted": self.encrypted,
        }


class StorageManager:
    """Manages USB mass storage for Eye Remote."""

    def __init__(self,
                 image_path: Path = STORAGE_IMAGE,
                 mount_path: Path = STORAGE_MOUNT,
                 size_mb: int = STORAGE_SIZE_MB):
        self._image_path = image_path
        self._mount_path = mount_path
        self._size_mb = size_mb
        self._audit_log: List[Dict[str, Any]] = []

    @property
    def image_path(self) -> Path:
        return self._image_path

    @property
    def mount_path(self) -> Path:
        return self._mount_path

    @property
    def is_mounted(self) -> bool:
        """Check if storage is mounted."""
        if not self._mount_path.exists():
            return False
        try:
            result = subprocess.run(
                ["mountpoint", "-q", str(self._mount_path)],
                capture_output=True
            )
            return result.returncode == 0
        except Exception:
            return False

    def get_info(self) -> StorageInfo:
        """Get storage information."""
        size_bytes = 0
        used_bytes = 0
        free_bytes = 0

        if self._image_path.exists():
            size_bytes = self._image_path.stat().st_size

        if self.is_mounted:
            try:
                st = os.statvfs(self._mount_path)
                size_bytes = st.f_blocks * st.f_frsize
                free_bytes = st.f_bavail * st.f_frsize
                used_bytes = size_bytes - free_bytes
            except Exception:
                pass

        return StorageInfo(
            image_path=str(self._image_path),
            mount_path=str(self._mount_path),
            mounted=self.is_mounted,
            size_bytes=size_bytes,
            used_bytes=used_bytes,
            free_bytes=free_bytes,
        )

    def create_storage(self, force: bool = False) -> bool:
        """Create the storage image file."""
        if self._image_path.exists() and not force:
            return True

        try:
            # Ensure parent directory exists
            self._image_path.parent.mkdir(parents=True, exist_ok=True)

            # Create image file
            subprocess.run(
                ["dd", "if=/dev/zero", f"of={self._image_path}",
                 "bs=1M", f"count={self._size_mb}"],
                capture_output=True, check=True
            )

            # Format as FAT32
            subprocess.run(
                ["mkfs.vfat", "-n", "EYEREMOTE", str(self._image_path)],
                capture_output=True, check=True
            )

            self._log_audit("create_storage", {"size_mb": self._size_mb})
            return True

        except subprocess.CalledProcessError as e:
            print(f"Failed to create storage: {e}")
            return False

    def mount(self) -> bool:
        """Mount the storage image."""
        if self.is_mounted:
            return True

        if not self._image_path.exists():
            if not self.create_storage():
                return False

        try:
            # Ensure mount point exists
            self._mount_path.mkdir(parents=True, exist_ok=True)

            # Mount the image
            subprocess.run(
                ["sudo", "mount", "-o", "loop,uid=1000,gid=1000",
                 str(self._image_path), str(self._mount_path)],
                capture_output=True, check=True
            )

            # Create directory structure
            self._ensure_directories()

            self._log_audit("mount", {"path": str(self._mount_path)})
            return True

        except subprocess.CalledProcessError as e:
            print(f"Failed to mount storage: {e}")
            return False

    def unmount(self) -> bool:
        """Unmount the storage image."""
        if not self.is_mounted:
            return True

        try:
            subprocess.run(
                ["sudo", "umount", str(self._mount_path)],
                capture_output=True, check=True
            )

            self._log_audit("unmount", {"path": str(self._mount_path)})
            return True

        except subprocess.CalledProcessError as e:
            print(f"Failed to unmount storage: {e}")
            return False

    def _ensure_directories(self):
        """Ensure storage directory structure exists."""
        if not self.is_mounted:
            return

        for dir_path in STORAGE_DIRS:
            full_path = self._mount_path / dir_path
            full_path.mkdir(parents=True, exist_ok=True)

    def list_files(self, subdir: str = "") -> List[FileInfo]:
        """List files in storage directory."""
        files = []

        if not self.is_mounted:
            return files

        target_path = self._mount_path / subdir
        if not target_path.exists():
            return files

        try:
            for item in target_path.iterdir():
                stat = item.stat()
                rel_path = str(item.relative_to(self._mount_path))

                files.append(FileInfo(
                    path=rel_path,
                    name=item.name,
                    size=stat.st_size,
                    modified=datetime.fromtimestamp(stat.st_mtime),
                    is_dir=item.is_dir(),
                    encrypted=item.suffix in ('.gpg', '.enc', '.aes'),
                ))
        except Exception as e:
            print(f"Error listing files: {e}")

        return files

    def read_file(self, path: str) -> Optional[bytes]:
        """Read a file from storage."""
        if not self.is_mounted:
            return None

        file_path = self._mount_path / path
        if not file_path.exists() or not file_path.is_file():
            return None

        try:
            self._log_audit("read_file", {"path": path})
            return file_path.read_bytes()
        except Exception as e:
            print(f"Error reading file: {e}")
            return None

    def write_file(self, path: str, data: bytes, overwrite: bool = False) -> bool:
        """Write a file to storage."""
        if not self.is_mounted:
            return False

        file_path = self._mount_path / path

        if file_path.exists() and not overwrite:
            return False

        try:
            # Ensure parent directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_bytes(data)

            self._log_audit("write_file", {"path": path, "size": len(data)})
            return True
        except Exception as e:
            print(f"Error writing file: {e}")
            return False

    def delete_file(self, path: str) -> bool:
        """Delete a file from storage."""
        if not self.is_mounted:
            return False

        file_path = self._mount_path / path

        if not file_path.exists():
            return True

        try:
            if file_path.is_dir():
                shutil.rmtree(file_path)
            else:
                file_path.unlink()

            self._log_audit("delete_file", {"path": path})
            return True
        except Exception as e:
            print(f"Error deleting file: {e}")
            return False

    def copy_to_storage(self, src: Path, dest: str) -> bool:
        """Copy a local file to storage."""
        if not self.is_mounted or not src.exists():
            return False

        dest_path = self._mount_path / dest

        try:
            dest_path.parent.mkdir(parents=True, exist_ok=True)

            if src.is_dir():
                shutil.copytree(src, dest_path, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dest_path)

            self._log_audit("copy_to_storage", {
                "src": str(src), "dest": dest
            })
            return True
        except Exception as e:
            print(f"Error copying to storage: {e}")
            return False

    def copy_from_storage(self, src: str, dest: Path) -> bool:
        """Copy a file from storage to local filesystem."""
        if not self.is_mounted:
            return False

        src_path = self._mount_path / src

        if not src_path.exists():
            return False

        try:
            dest.parent.mkdir(parents=True, exist_ok=True)

            if src_path.is_dir():
                shutil.copytree(src_path, dest, dirs_exist_ok=True)
            else:
                shutil.copy2(src_path, dest)

            self._log_audit("copy_from_storage", {
                "src": src, "dest": str(dest)
            })
            return True
        except Exception as e:
            print(f"Error copying from storage: {e}")
            return False

    def get_free_space(self) -> int:
        """Get free space in bytes."""
        info = self.get_info()
        return info.free_bytes

    def sync(self) -> bool:
        """Sync filesystem buffers."""
        if not self.is_mounted:
            return False

        try:
            subprocess.run(["sync"], check=True)
            return True
        except Exception:
            return False

    def _log_audit(self, action: str, details: Dict[str, Any]):
        """Log an audit entry."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details,
        }
        self._audit_log.append(entry)

        # Write to audit log file if mounted
        if self.is_mounted:
            try:
                log_path = self._mount_path / "logs" / "audit" / "operations.jsonl"
                log_path.parent.mkdir(parents=True, exist_ok=True)
                with open(log_path, "a") as f:
                    f.write(json.dumps(entry) + "\n")
            except Exception:
                pass

    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent audit log entries."""
        return self._audit_log[-limit:]


# Singleton instance
_storage_manager: Optional[StorageManager] = None


def get_storage_manager() -> StorageManager:
    """Get singleton storage manager."""
    global _storage_manager
    if _storage_manager is None:
        _storage_manager = StorageManager()
    return _storage_manager
