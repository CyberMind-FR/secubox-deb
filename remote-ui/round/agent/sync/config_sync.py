#!/usr/bin/env python3
"""
SecuBox Eye Remote - Configuration Sync

Synchronizes configurations between Eye Remote and SecuBox.
Supports bidirectional sync with conflict detection.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import os
import json
import hashlib
import aiohttp
import asyncio
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any

from .storage_manager import get_storage_manager, StorageManager


# API endpoints
API_BASE_OTG = "http://10.55.0.1:8000"
API_BASE_WIFI = "http://secubox.local:8000"

# Sync paths
CONFIGS_DIR = "configs/secubox"


class SyncDirection(Enum):
    """Direction of sync operation."""
    EXPORT = "export"  # SecuBox → Eye Remote
    IMPORT = "import"  # Eye Remote → SecuBox
    BIDIRECTIONAL = "bidirectional"


class SyncStatus(Enum):
    """Status of a sync operation."""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    NO_CHANGES = "no_changes"
    CONFLICT = "conflict"


@dataclass
class SyncResult:
    """Result of a sync operation."""
    status: SyncStatus
    message: str
    synced_files: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "message": self.message,
            "synced_files": self.synced_files,
            "conflicts": self.conflicts,
            "errors": self.errors,
            "duration_ms": self.duration_ms,
        }


@dataclass
class ConfigFile:
    """Represents a configuration file."""
    path: str
    module: str
    checksum: str
    modified: datetime
    size: int
    content: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "module": self.module,
            "checksum": self.checksum,
            "modified": self.modified.isoformat(),
            "size": self.size,
        }


class ConfigSync:
    """Handles configuration synchronization."""

    # Modules that can be synced
    SYNCABLE_MODULES = [
        "system",
        "wireguard",
        "crowdsec",
        "firewall",
        "auth",
        "dpi",
        "dns",
        "qos",
        "netmodes",
    ]

    # API timeout
    TIMEOUT = 10

    def __init__(self, storage: Optional[StorageManager] = None):
        self._storage = storage or get_storage_manager()
        self._api_base = API_BASE_OTG
        self._jwt_token: Optional[str] = None
        self._last_sync: Optional[datetime] = None

    def set_api_base(self, url: str):
        """Set API base URL."""
        self._api_base = url

    def set_jwt_token(self, token: str):
        """Set JWT token for API authentication."""
        self._jwt_token = token

    async def _api_request(self,
                           method: str,
                           endpoint: str,
                           data: Optional[Dict] = None) -> Optional[Dict]:
        """Make an API request to SecuBox."""
        headers = {"Content-Type": "application/json"}
        if self._jwt_token:
            headers["Authorization"] = f"Bearer {self._jwt_token}"

        url = f"{self._api_base}{endpoint}"

        try:
            timeout = aiohttp.ClientTimeout(total=self.TIMEOUT)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                if method == "GET":
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            return await resp.json()
                elif method == "POST":
                    async with session.post(url, headers=headers, json=data) as resp:
                        if resp.status in (200, 201):
                            return await resp.json()
                elif method == "PUT":
                    async with session.put(url, headers=headers, json=data) as resp:
                        if resp.status == 200:
                            return await resp.json()
        except Exception as e:
            print(f"API request failed: {e}")

        return None

    def _calculate_checksum(self, data: bytes) -> str:
        """Calculate SHA-256 checksum."""
        return hashlib.sha256(data).hexdigest()

    def _get_local_configs(self, modules: Optional[List[str]] = None) -> List[ConfigFile]:
        """Get list of local config files in storage."""
        configs = []

        if not self._storage.is_mounted:
            return configs

        target_modules = modules or self.SYNCABLE_MODULES
        configs_path = self._storage.mount_path / CONFIGS_DIR

        for module in target_modules:
            module_path = configs_path / module
            if not module_path.exists():
                continue

            for file_path in module_path.rglob("*"):
                if file_path.is_file():
                    try:
                        content = file_path.read_bytes()
                        stat = file_path.stat()

                        configs.append(ConfigFile(
                            path=str(file_path.relative_to(configs_path)),
                            module=module,
                            checksum=self._calculate_checksum(content),
                            modified=datetime.fromtimestamp(stat.st_mtime),
                            size=stat.st_size,
                            content=content,
                        ))
                    except Exception as e:
                        print(f"Error reading config: {e}")

        return configs

    async def _get_remote_configs(self,
                                  modules: Optional[List[str]] = None) -> List[ConfigFile]:
        """Get list of config files from SecuBox."""
        configs = []
        target_modules = modules or self.SYNCABLE_MODULES

        for module in target_modules:
            result = await self._api_request(
                "GET",
                f"/api/v1/{module}/config/export"
            )

            if result and "files" in result:
                for file_info in result["files"]:
                    configs.append(ConfigFile(
                        path=file_info["path"],
                        module=module,
                        checksum=file_info.get("checksum", ""),
                        modified=datetime.fromisoformat(file_info.get("modified", datetime.now().isoformat())),
                        size=file_info.get("size", 0),
                    ))

        return configs

    async def export_configs(self,
                             modules: Optional[List[str]] = None) -> SyncResult:
        """Export configs from SecuBox to Eye Remote storage."""
        start_time = datetime.now()

        if not self._storage.is_mounted:
            if not self._storage.mount():
                return SyncResult(
                    status=SyncStatus.FAILED,
                    message="Failed to mount storage"
                )

        target_modules = modules or self.SYNCABLE_MODULES
        synced_files = []
        errors = []

        for module in target_modules:
            # Request config export from SecuBox
            result = await self._api_request(
                "POST",
                f"/api/v1/{module}/config/export",
                {"format": "json"}
            )

            if not result:
                errors.append(f"Failed to export {module}")
                continue

            # Save exported config to storage
            if "content" in result:
                dest_path = f"{CONFIGS_DIR}/{module}/config.json"
                content = json.dumps(result["content"], indent=2).encode()

                if self._storage.write_file(dest_path, content, overwrite=True):
                    synced_files.append(dest_path)
                else:
                    errors.append(f"Failed to write {dest_path}")

            # Save individual files if provided
            if "files" in result:
                for file_info in result["files"]:
                    file_path = file_info.get("path", "")
                    file_content = file_info.get("content", "")

                    if file_path and file_content:
                        dest_path = f"{CONFIGS_DIR}/{module}/{file_path}"
                        content = file_content.encode() if isinstance(file_content, str) else file_content

                        if self._storage.write_file(dest_path, content, overwrite=True):
                            synced_files.append(dest_path)
                        else:
                            errors.append(f"Failed to write {dest_path}")

        self._storage.sync()
        self._last_sync = datetime.now()

        duration = (datetime.now() - start_time).total_seconds() * 1000

        if not synced_files and errors:
            status = SyncStatus.FAILED
        elif errors:
            status = SyncStatus.PARTIAL
        elif synced_files:
            status = SyncStatus.SUCCESS
        else:
            status = SyncStatus.NO_CHANGES

        return SyncResult(
            status=status,
            message=f"Exported {len(synced_files)} files from {len(target_modules)} modules",
            synced_files=synced_files,
            errors=errors,
            duration_ms=duration,
        )

    async def import_configs(self,
                             modules: Optional[List[str]] = None,
                             validate: bool = True,
                             dry_run: bool = False) -> SyncResult:
        """Import configs from Eye Remote storage to SecuBox."""
        start_time = datetime.now()

        if not self._storage.is_mounted:
            return SyncResult(
                status=SyncStatus.FAILED,
                message="Storage not mounted"
            )

        local_configs = self._get_local_configs(modules)
        if not local_configs:
            return SyncResult(
                status=SyncStatus.NO_CHANGES,
                message="No local configs found"
            )

        synced_files = []
        errors = []
        conflicts = []

        # Group by module
        by_module: Dict[str, List[ConfigFile]] = {}
        for config in local_configs:
            if config.module not in by_module:
                by_module[config.module] = []
            by_module[config.module].append(config)

        for module, configs in by_module.items():
            # Build import payload
            files_data = []
            for config in configs:
                if config.content:
                    try:
                        content = config.content.decode("utf-8")
                    except UnicodeDecodeError:
                        import base64
                        content = base64.b64encode(config.content).decode()

                    files_data.append({
                        "path": config.path.replace(f"{module}/", "", 1),
                        "content": content,
                        "checksum": config.checksum,
                    })

            if dry_run:
                synced_files.extend([c.path for c in configs])
                continue

            # Send import request
            result = await self._api_request(
                "POST",
                f"/api/v1/{module}/config/import",
                {
                    "files": files_data,
                    "validate": validate,
                }
            )

            if result:
                if result.get("status") == "success":
                    synced_files.extend([c.path for c in configs])
                elif result.get("status") == "conflict":
                    conflicts.extend(result.get("conflicts", []))
                else:
                    errors.append(result.get("message", f"Import failed for {module}"))
            else:
                errors.append(f"API request failed for {module}")

        duration = (datetime.now() - start_time).total_seconds() * 1000
        self._last_sync = datetime.now()

        if conflicts:
            status = SyncStatus.CONFLICT
        elif not synced_files and errors:
            status = SyncStatus.FAILED
        elif errors:
            status = SyncStatus.PARTIAL
        elif synced_files:
            status = SyncStatus.SUCCESS
        else:
            status = SyncStatus.NO_CHANGES

        return SyncResult(
            status=status,
            message=f"{'Would import' if dry_run else 'Imported'} {len(synced_files)} files",
            synced_files=synced_files,
            conflicts=conflicts,
            errors=errors,
            duration_ms=duration,
        )

    async def check_sync_status(self,
                                modules: Optional[List[str]] = None) -> Dict[str, Any]:
        """Check sync status between local and remote configs."""
        local_configs = self._get_local_configs(modules)
        remote_configs = await self._get_remote_configs(modules)

        # Build lookup maps
        local_map = {c.path: c for c in local_configs}
        remote_map = {c.path: c for c in remote_configs}

        all_paths = set(local_map.keys()) | set(remote_map.keys())

        in_sync = []
        local_newer = []
        remote_newer = []
        local_only = []
        remote_only = []

        for path in all_paths:
            local = local_map.get(path)
            remote = remote_map.get(path)

            if local and remote:
                if local.checksum == remote.checksum:
                    in_sync.append(path)
                elif local.modified > remote.modified:
                    local_newer.append(path)
                else:
                    remote_newer.append(path)
            elif local:
                local_only.append(path)
            else:
                remote_only.append(path)

        return {
            "in_sync": len(in_sync),
            "local_newer": local_newer,
            "remote_newer": remote_newer,
            "local_only": local_only,
            "remote_only": remote_only,
            "last_sync": self._last_sync.isoformat() if self._last_sync else None,
        }

    def get_sync_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get sync history from audit log."""
        if not self._storage.is_mounted:
            return []

        history = []
        log_path = self._storage.mount_path / "logs" / "audit" / "sync.jsonl"

        if log_path.exists():
            try:
                with open(log_path) as f:
                    lines = f.readlines()
                    for line in lines[-limit:]:
                        history.append(json.loads(line))
            except Exception:
                pass

        return history


# Singleton instance
_config_sync: Optional[ConfigSync] = None


def get_config_sync() -> ConfigSync:
    """Get singleton config sync instance."""
    global _config_sync
    if _config_sync is None:
        _config_sync = ConfigSync()
    return _config_sync
