# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Eye Remote - Sync Module

Handles configuration sync and backup between Eye Remote and SecuBox.

CyberMind - https://cybermind.fr
"""

from .storage_manager import (
    StorageManager,
    get_storage_manager,
    StorageInfo,
)

from .backup_manager import (
    BackupManager,
    get_backup_manager,
    BackupInfo,
    BackupResult,
    BackupType,
)

from .config_sync import (
    ConfigSync,
    get_config_sync,
    SyncDirection,
    SyncResult,
)

__all__ = [
    'StorageManager',
    'get_storage_manager',
    'StorageInfo',
    'BackupManager',
    'get_backup_manager',
    'BackupInfo',
    'BackupResult',
    'BackupType',
    'ConfigSync',
    'get_config_sync',
    'SyncDirection',
    'SyncResult',
]
