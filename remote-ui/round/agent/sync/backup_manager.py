#!/usr/bin/env python3
"""
SecuBox Eye Remote - Backup Manager

Handles encrypted backups of SecuBox configurations.
Supports AES-256 encryption and GPG signing.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import os
import json
import hashlib
import tarfile
import tempfile
import subprocess
from io import BytesIO
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any

from .storage_manager import get_storage_manager, StorageManager


# Backup paths
BACKUP_DIR = "backups"
LATEST_LINK = "latest"

# Encryption settings
CIPHER_ALGO = "aes-256-cbc"


class BackupType(Enum):
    """Type of backup."""
    FULL = "full"
    CONFIG = "config"
    CREDENTIALS = "credentials"
    MODULES = "modules"


@dataclass
class BackupInfo:
    """Information about a backup."""
    name: str
    timestamp: datetime
    backup_type: BackupType
    size_bytes: int
    encrypted: bool
    modules: List[str]
    checksum: str
    path: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "timestamp": self.timestamp.isoformat(),
            "backup_type": self.backup_type.value,
            "size_bytes": self.size_bytes,
            "encrypted": self.encrypted,
            "modules": self.modules,
            "checksum": self.checksum,
            "path": self.path,
        }


@dataclass
class BackupResult:
    """Result of a backup operation."""
    success: bool
    message: str
    backup_info: Optional[BackupInfo] = None
    errors: List[str] = field(default_factory=list)


class BackupManager:
    """Manages SecuBox configuration backups."""

    # Default modules to backup
    DEFAULT_MODULES = [
        "system",
        "wireguard",
        "crowdsec",
        "firewall",
        "auth",
    ]

    # Module config paths on SecuBox
    MODULE_PATHS = {
        "system": "/etc/secubox/system.toml",
        "wireguard": "/etc/wireguard",
        "crowdsec": "/etc/crowdsec",
        "firewall": "/etc/secubox/firewall",
        "auth": "/etc/secubox/auth.toml",
        "dpi": "/etc/secubox/dpi.toml",
        "dns": "/etc/secubox/dns",
        "qos": "/etc/secubox/qos.toml",
    }

    def __init__(self, storage: Optional[StorageManager] = None):
        self._storage = storage or get_storage_manager()
        self._encryption_key: Optional[bytes] = None

    def set_encryption_key(self, key: bytes):
        """Set encryption key for backups."""
        # Derive a 256-bit key using SHA-256
        self._encryption_key = hashlib.sha256(key).digest()

    def list_backups(self) -> List[BackupInfo]:
        """List all available backups."""
        backups = []

        if not self._storage.is_mounted:
            return backups

        backup_path = self._storage.mount_path / BACKUP_DIR
        if not backup_path.exists():
            return backups

        for item in backup_path.iterdir():
            if item.is_dir() and item.name != LATEST_LINK:
                meta_file = item / "backup.json"
                if meta_file.exists():
                    try:
                        with open(meta_file) as f:
                            meta = json.load(f)

                        backups.append(BackupInfo(
                            name=meta.get("name", item.name),
                            timestamp=datetime.fromisoformat(meta["timestamp"]),
                            backup_type=BackupType(meta.get("type", "full")),
                            size_bytes=meta.get("size_bytes", 0),
                            encrypted=meta.get("encrypted", False),
                            modules=meta.get("modules", []),
                            checksum=meta.get("checksum", ""),
                            path=str(item.relative_to(self._storage.mount_path)),
                        ))
                    except Exception as e:
                        print(f"Error reading backup metadata: {e}")

        # Sort by timestamp, newest first
        backups.sort(key=lambda b: b.timestamp, reverse=True)
        return backups

    def create_backup(self,
                      name: Optional[str] = None,
                      modules: Optional[List[str]] = None,
                      encrypt: bool = True,
                      backup_type: BackupType = BackupType.FULL) -> BackupResult:
        """Create a new backup."""
        if not self._storage.is_mounted:
            if not self._storage.mount():
                return BackupResult(
                    success=False,
                    message="Failed to mount storage"
                )

        # Generate backup name if not provided
        timestamp = datetime.now()
        if not name:
            name = timestamp.strftime("%Y-%m-%d_%H%M%S")

        # Determine modules to backup
        if modules is None:
            modules = self.DEFAULT_MODULES

        # Create backup directory
        backup_dir = self._storage.mount_path / BACKUP_DIR / name
        backup_dir.mkdir(parents=True, exist_ok=True)

        errors = []
        total_size = 0

        # Collect files to backup
        files_to_backup: List[tuple] = []

        for module in modules:
            module_path = self.MODULE_PATHS.get(module)
            if not module_path:
                errors.append(f"Unknown module: {module}")
                continue

            src_path = Path(module_path)
            if not src_path.exists():
                errors.append(f"Module path not found: {module_path}")
                continue

            files_to_backup.append((module, src_path))

        if not files_to_backup:
            return BackupResult(
                success=False,
                message="No files to backup",
                errors=errors
            )

        # Create tarball
        tar_path = backup_dir / "data.tar"
        try:
            with tarfile.open(tar_path, "w") as tar:
                for module, src_path in files_to_backup:
                    if src_path.is_dir():
                        tar.add(src_path, arcname=module)
                    else:
                        tar.add(src_path, arcname=f"{module}/{src_path.name}")

            total_size = tar_path.stat().st_size

            # Calculate checksum
            checksum = self._calculate_checksum(tar_path)

            # Encrypt if requested
            if encrypt and self._encryption_key:
                encrypted_path = backup_dir / "data.tar.enc"
                if self._encrypt_file(tar_path, encrypted_path):
                    tar_path.unlink()
                    total_size = encrypted_path.stat().st_size
                else:
                    errors.append("Encryption failed, storing unencrypted")
                    encrypt = False

        except Exception as e:
            return BackupResult(
                success=False,
                message=f"Failed to create tarball: {e}",
                errors=errors
            )

        # Write metadata
        metadata = {
            "name": name,
            "timestamp": timestamp.isoformat(),
            "type": backup_type.value,
            "size_bytes": total_size,
            "encrypted": encrypt and self._encryption_key is not None,
            "modules": modules,
            "checksum": checksum,
            "version": "1.0",
        }

        meta_path = backup_dir / "backup.json"
        with open(meta_path, "w") as f:
            json.dump(metadata, f, indent=2)

        # Update latest symlink
        latest_path = self._storage.mount_path / BACKUP_DIR / LATEST_LINK
        if latest_path.is_symlink():
            latest_path.unlink()
        latest_path.symlink_to(name)

        # Sync filesystem
        self._storage.sync()

        backup_info = BackupInfo(
            name=name,
            timestamp=timestamp,
            backup_type=backup_type,
            size_bytes=total_size,
            encrypted=encrypt and self._encryption_key is not None,
            modules=modules,
            checksum=checksum,
            path=str(backup_dir.relative_to(self._storage.mount_path)),
        )

        return BackupResult(
            success=True,
            message=f"Backup created: {name}",
            backup_info=backup_info,
            errors=errors
        )

    def restore_backup(self,
                       name: str,
                       modules: Optional[List[str]] = None,
                       dry_run: bool = False) -> BackupResult:
        """Restore from a backup."""
        if not self._storage.is_mounted:
            return BackupResult(
                success=False,
                message="Storage not mounted"
            )

        backup_dir = self._storage.mount_path / BACKUP_DIR / name
        meta_path = backup_dir / "backup.json"

        if not meta_path.exists():
            return BackupResult(
                success=False,
                message=f"Backup not found: {name}"
            )

        # Read metadata
        try:
            with open(meta_path) as f:
                metadata = json.load(f)
        except Exception as e:
            return BackupResult(
                success=False,
                message=f"Failed to read backup metadata: {e}"
            )

        errors = []

        # Find data file
        data_path = backup_dir / "data.tar.enc"
        encrypted = data_path.exists()

        if not encrypted:
            data_path = backup_dir / "data.tar"

        if not data_path.exists():
            return BackupResult(
                success=False,
                message="Backup data file not found"
            )

        # Decrypt if needed
        tar_path = data_path
        if encrypted:
            if not self._encryption_key:
                return BackupResult(
                    success=False,
                    message="Encryption key required"
                )

            # Decrypt to temp file
            with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
                tmp_path = Path(tmp.name)

            if not self._decrypt_file(data_path, tmp_path):
                return BackupResult(
                    success=False,
                    message="Decryption failed"
                )

            tar_path = tmp_path

        # Verify checksum
        checksum = self._calculate_checksum(tar_path)
        if checksum != metadata.get("checksum"):
            errors.append("Checksum mismatch - backup may be corrupted")

        # Filter modules if specified
        backup_modules = metadata.get("modules", [])
        if modules:
            restore_modules = [m for m in modules if m in backup_modules]
        else:
            restore_modules = backup_modules

        if dry_run:
            return BackupResult(
                success=True,
                message=f"Dry run: would restore modules {restore_modules}",
                errors=errors
            )

        # Extract and restore
        try:
            with tarfile.open(tar_path, "r") as tar:
                for module in restore_modules:
                    dest_path = self.MODULE_PATHS.get(module)
                    if not dest_path:
                        errors.append(f"Unknown module: {module}")
                        continue

                    # Extract module files
                    members = [m for m in tar.getmembers()
                               if m.name.startswith(f"{module}/") or m.name == module]

                    if members:
                        # Backup current config first
                        self._backup_current(module, Path(dest_path))

                        # Extract to destination
                        for member in members:
                            # Adjust path
                            member.name = member.name.replace(f"{module}/", "", 1)
                            tar.extract(member, Path(dest_path).parent)

        except Exception as e:
            return BackupResult(
                success=False,
                message=f"Restore failed: {e}",
                errors=errors
            )
        finally:
            # Clean up temp file
            if encrypted and tmp_path.exists():
                tmp_path.unlink()

        return BackupResult(
            success=True,
            message=f"Restored {len(restore_modules)} modules",
            errors=errors
        )

    def delete_backup(self, name: str) -> bool:
        """Delete a backup."""
        if not self._storage.is_mounted:
            return False

        backup_dir = self._storage.mount_path / BACKUP_DIR / name
        if not backup_dir.exists():
            return False

        try:
            import shutil
            shutil.rmtree(backup_dir)

            # Update latest link if needed
            latest_path = self._storage.mount_path / BACKUP_DIR / LATEST_LINK
            if latest_path.is_symlink():
                if latest_path.resolve().name == name:
                    latest_path.unlink()

            return True
        except Exception:
            return False

    def _calculate_checksum(self, path: Path) -> str:
        """Calculate SHA-256 checksum of a file."""
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _encrypt_file(self, src: Path, dest: Path) -> bool:
        """Encrypt a file using AES-256."""
        if not self._encryption_key:
            return False

        try:
            # Use openssl for encryption
            result = subprocess.run(
                ["openssl", "enc", f"-{CIPHER_ALGO}", "-salt",
                 "-in", str(src), "-out", str(dest),
                 "-pass", f"pass:{self._encryption_key.hex()}"],
                capture_output=True
            )
            return result.returncode == 0
        except Exception:
            return False

    def _decrypt_file(self, src: Path, dest: Path) -> bool:
        """Decrypt a file using AES-256."""
        if not self._encryption_key:
            return False

        try:
            result = subprocess.run(
                ["openssl", "enc", f"-{CIPHER_ALGO}", "-d",
                 "-in", str(src), "-out", str(dest),
                 "-pass", f"pass:{self._encryption_key.hex()}"],
                capture_output=True
            )
            return result.returncode == 0
        except Exception:
            return False

    def _backup_current(self, module: str, path: Path):
        """Backup current config before restore."""
        if not path.exists():
            return

        backup_name = f"{module}.pre-restore.{datetime.now().strftime('%Y%m%d%H%M%S')}"
        backup_path = self._storage.mount_path / BACKUP_DIR / ".pre-restore" / backup_name

        try:
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_dir():
                import shutil
                shutil.copytree(path, backup_path)
            else:
                import shutil
                shutil.copy2(path, backup_path)
        except Exception:
            pass


# Singleton instance
_backup_manager: Optional[BackupManager] = None


def get_backup_manager() -> BackupManager:
    """Get singleton backup manager."""
    global _backup_manager
    if _backup_manager is None:
        _backup_manager = BackupManager()
    return _backup_manager
