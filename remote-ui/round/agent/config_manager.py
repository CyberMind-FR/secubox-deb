# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Eye Remote — Configuration Manager
Double-buffered config with droplet patches and 4R rollback

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""

import os
import json
import shutil
import fcntl
import hashlib
import tomllib
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)

# Base paths
DATA_ROOT = Path("/data/configs")
ACTIVE_DIR = DATA_ROOT / "active"
SHADOW_DIR = DATA_ROOT / "shadow"
PATCHES_DIR = SHADOW_DIR / "patches"
ROLLBACK_DIR = DATA_ROOT / "rollback"
LOCKFILE = DATA_ROOT / "lockfile"
STATE_FILE = DATA_ROOT / "state.json"

# Rollback slots
ROLLBACK_SLOTS = ["R1", "R2", "R3", "R4"]
MAX_ROLLBACKS = 4


@dataclass
class ConfigState:
    """Current configuration state"""
    active_hash: str = ""
    shadow_hash: str = ""
    last_swap_at: Optional[str] = None
    pending_patches: List[str] = field(default_factory=list)
    rollback_count: int = 0
    locked: bool = False
    locked_by: Optional[str] = None
    locked_at: Optional[str] = None


class ConfigLock:
    """Context manager for configuration lock"""

    def __init__(self, manager: 'ConfigManager', owner: str = "unknown"):
        self.manager = manager
        self.owner = owner
        self.fd = None
        self.acquired = False

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()
        return False

    def acquire(self) -> bool:
        """Acquire exclusive lock"""
        LOCKFILE.parent.mkdir(parents=True, exist_ok=True)
        self.fd = open(LOCKFILE, 'w')
        try:
            fcntl.flock(self.fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.acquired = True
            # Write lock info
            self.fd.write(json.dumps({
                "owner": self.owner,
                "pid": os.getpid(),
                "acquired_at": datetime.now().isoformat()
            }))
            self.fd.flush()
            logger.info(f"Lock acquired by {self.owner}")
            return True
        except (IOError, OSError):
            self.fd.close()
            self.fd = None
            logger.warning(f"Lock acquisition failed for {self.owner}")
            return False

    def release(self):
        """Release lock"""
        if self.fd and self.acquired:
            fcntl.flock(self.fd.fileno(), fcntl.LOCK_UN)
            self.fd.close()
            self.fd = None
            self.acquired = False
            # Clear lockfile
            try:
                LOCKFILE.unlink()
            except FileNotFoundError:
                pass
            logger.info(f"Lock released by {self.owner}")


class ConfigManager:
    """
    Double-buffered configuration manager with droplet patches

    Architecture:
    - active/  : Live configuration (read-only during operation)
    - shadow/  : Editable copy for modifications
    - patches/ : Droplet patches to apply
    - rollback/: R1-R4 snapshots for recovery

    Workflow:
    1. Drop patches into shadow/patches/
    2. Acquire lock
    3. Apply patches to shadow
    4. Validate configuration
    5. Atomic swap (shadow → active)
    6. Shift rollbacks (active → R1 → R2 → R3 → R4)
    7. Release lock
    """

    def __init__(self, data_root: Optional[Path] = None):
        if data_root:
            global DATA_ROOT, ACTIVE_DIR, SHADOW_DIR, PATCHES_DIR, ROLLBACK_DIR, LOCKFILE, STATE_FILE
            DATA_ROOT = data_root
            ACTIVE_DIR = DATA_ROOT / "active"
            SHADOW_DIR = DATA_ROOT / "shadow"
            PATCHES_DIR = SHADOW_DIR / "patches"
            ROLLBACK_DIR = DATA_ROOT / "rollback"
            LOCKFILE = DATA_ROOT / "lockfile"
            STATE_FILE = DATA_ROOT / "state.json"

        self._ensure_directories()

    def _ensure_directories(self):
        """Create directory structure if not exists"""
        for d in [ACTIVE_DIR, SHADOW_DIR, PATCHES_DIR, ROLLBACK_DIR]:
            d.mkdir(parents=True, exist_ok=True)

        for slot in ROLLBACK_SLOTS:
            (ROLLBACK_DIR / slot).mkdir(exist_ok=True)

    def _compute_hash(self, directory: Path) -> str:
        """Compute SHA256 hash of all config files in directory"""
        hasher = hashlib.sha256()

        if not directory.exists():
            return ""

        for f in sorted(directory.glob("*.toml")):
            hasher.update(f.name.encode())
            hasher.update(f.read_bytes())

        return hasher.hexdigest()[:16]

    def get_state(self) -> ConfigState:
        """Get current configuration state"""
        state = ConfigState()

        state.active_hash = self._compute_hash(ACTIVE_DIR)
        state.shadow_hash = self._compute_hash(SHADOW_DIR)

        # Count pending patches
        if PATCHES_DIR.exists():
            state.pending_patches = [
                p.name for p in PATCHES_DIR.glob("*.patch")
            ] + [
                p.name for p in PATCHES_DIR.glob("*.toml")
            ]

        # Count available rollbacks
        state.rollback_count = sum(
            1 for slot in ROLLBACK_SLOTS
            if list((ROLLBACK_DIR / slot).glob("*.toml"))
        )

        # Check lock status
        if LOCKFILE.exists():
            try:
                with open(LOCKFILE) as f:
                    lock_info = json.load(f)
                    state.locked = True
                    state.locked_by = lock_info.get("owner")
                    state.locked_at = lock_info.get("acquired_at")
            except (json.JSONDecodeError, FileNotFoundError):
                pass

        # Load last swap time
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE) as f:
                    saved = json.load(f)
                    state.last_swap_at = saved.get("last_swap_at")
            except (json.JSONDecodeError, FileNotFoundError):
                pass

        return state

    def lock(self, owner: str = "unknown") -> ConfigLock:
        """Get a configuration lock context manager"""
        return ConfigLock(self, owner)

    def read_active(self, name: str) -> Dict[str, Any]:
        """Read active configuration file"""
        config_file = ACTIVE_DIR / f"{name}.toml"
        if not config_file.exists():
            return {}

        with open(config_file, 'rb') as f:
            return tomllib.load(f)

    def read_shadow(self, name: str) -> Dict[str, Any]:
        """Read shadow configuration file"""
        config_file = SHADOW_DIR / f"{name}.toml"
        if not config_file.exists():
            # Initialize from active if shadow doesn't exist
            active_file = ACTIVE_DIR / f"{name}.toml"
            if active_file.exists():
                shutil.copy2(active_file, config_file)
                with open(config_file, 'rb') as f:
                    return tomllib.load(f)
            return {}

        with open(config_file, 'rb') as f:
            return tomllib.load(f)

    def write_shadow(self, name: str, config: Dict[str, Any]):
        """Write configuration to shadow"""
        config_file = SHADOW_DIR / f"{name}.toml"

        # Convert dict to TOML format
        lines = self._dict_to_toml(config)
        config_file.write_text("\n".join(lines))

        logger.info(f"Written shadow config: {name}")

    def _dict_to_toml(self, d: Dict[str, Any], prefix: str = "") -> List[str]:
        """Convert dictionary to TOML lines"""
        lines = []

        # First pass: simple values
        for key, value in d.items():
            if isinstance(value, dict):
                continue
            lines.append(self._format_toml_value(key, value))

        # Second pass: tables
        for key, value in d.items():
            if isinstance(value, dict):
                section = f"{prefix}.{key}" if prefix else key
                lines.append(f"\n[{section}]")
                lines.extend(self._dict_to_toml(value, section))

        return lines

    def _format_toml_value(self, key: str, value: Any) -> str:
        """Format a single TOML key-value pair"""
        if isinstance(value, bool):
            return f"{key} = {str(value).lower()}"
        elif isinstance(value, (int, float)):
            return f"{key} = {value}"
        elif isinstance(value, str):
            return f'{key} = "{value}"'
        elif isinstance(value, list):
            items = ", ".join(
                f'"{v}"' if isinstance(v, str) else str(v)
                for v in value
            )
            return f"{key} = [{items}]"
        else:
            return f'{key} = "{value}"'

    def add_patch(self, name: str, content: str) -> Path:
        """Add a patch file to pending patches"""
        patch_file = PATCHES_DIR / name
        patch_file.write_text(content)
        logger.info(f"Added patch: {name}")
        return patch_file

    def apply_patches(self) -> List[str]:
        """Apply all pending patches to shadow config"""
        applied = []

        # Process .toml patches (full replacement)
        for patch_file in sorted(PATCHES_DIR.glob("*.toml")):
            target = patch_file.stem  # e.g., "network.toml" -> "network"

            # Copy patch to shadow
            shutil.copy2(patch_file, SHADOW_DIR / patch_file.name)
            applied.append(patch_file.name)

            # Remove applied patch
            patch_file.unlink()
            logger.info(f"Applied TOML patch: {patch_file.name}")

        # Process .patch files (key-value updates)
        for patch_file in sorted(PATCHES_DIR.glob("*.patch")):
            try:
                patch_content = patch_file.read_text()
                self._apply_kv_patch(patch_content)
                applied.append(patch_file.name)
                patch_file.unlink()
                logger.info(f"Applied KV patch: {patch_file.name}")
            except Exception as e:
                logger.error(f"Failed to apply patch {patch_file.name}: {e}")

        return applied

    def _apply_kv_patch(self, content: str):
        """
        Apply key-value patch format:

        target: eye-remote
        ---
        display.brightness = 100
        display.theme = "cyber"
        network.wifi_ssid = "MyNetwork"
        """
        lines = content.strip().split("\n")
        target = "eye-remote"  # default

        # Parse header
        for i, line in enumerate(lines):
            if line.strip() == "---":
                lines = lines[i+1:]
                break
            if line.startswith("target:"):
                target = line.split(":", 1)[1].strip()

        # Load current shadow config
        config = self.read_shadow(target)

        # Apply updates
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if "=" not in line:
                continue

            key_path, value = line.split("=", 1)
            key_path = key_path.strip()
            value = value.strip()

            # Parse value
            if value.lower() == "true":
                value = True
            elif value.lower() == "false":
                value = False
            elif value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            else:
                try:
                    value = int(value)
                except ValueError:
                    try:
                        value = float(value)
                    except ValueError:
                        pass

            # Navigate to nested key
            keys = key_path.split(".")
            current = config
            for key in keys[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]

            current[keys[-1]] = value

        # Write back
        self.write_shadow(target, config)

    def validate_shadow(self) -> tuple[bool, str]:
        """Validate shadow configuration before swap"""
        errors = []

        for config_file in SHADOW_DIR.glob("*.toml"):
            try:
                with open(config_file, 'rb') as f:
                    tomllib.load(f)
            except Exception as e:
                errors.append(f"{config_file.name}: {e}")

        if errors:
            return False, "; ".join(errors)

        return True, "OK"

    def swap(self) -> bool:
        """
        Atomic swap: shadow → active

        1. Validate shadow config
        2. Shift rollbacks (active → R1 → R2 → R3 → R4)
        3. Swap shadow ↔ active
        4. Update state
        """
        # Validate first
        valid, msg = self.validate_shadow()
        if not valid:
            logger.error(f"Swap aborted: validation failed - {msg}")
            return False

        # Shift rollbacks
        self._shift_rollbacks()

        # Archive current active to R1
        r1_dir = ROLLBACK_DIR / "R1"
        for f in r1_dir.glob("*"):
            f.unlink()
        for f in ACTIVE_DIR.glob("*.toml"):
            shutil.copy2(f, r1_dir / f.name)

        # Swap shadow → active
        for f in ACTIVE_DIR.glob("*.toml"):
            f.unlink()
        for f in SHADOW_DIR.glob("*.toml"):
            shutil.copy2(f, ACTIVE_DIR / f.name)

        # Update state
        self._save_state({
            "last_swap_at": datetime.now().isoformat(),
            "active_hash": self._compute_hash(ACTIVE_DIR),
        })

        logger.info("Config swap completed successfully")
        return True

    def _shift_rollbacks(self):
        """Shift rollback slots: R1→R2→R3���R4, discard R4"""
        # R4 is discarded, R3→R4, R2→R3, R1→R2
        for i in range(MAX_ROLLBACKS - 1, 0, -1):
            src = ROLLBACK_DIR / ROLLBACK_SLOTS[i - 1]
            dst = ROLLBACK_DIR / ROLLBACK_SLOTS[i]

            # Clear destination
            for f in dst.glob("*"):
                f.unlink()

            # Move source to destination
            for f in src.glob("*.toml"):
                shutil.copy2(f, dst / f.name)

    def rollback(self, slot: str = "R1") -> bool:
        """
        Rollback to a previous configuration

        Args:
            slot: R1 (most recent), R2, R3, or R4 (oldest)
        """
        if slot not in ROLLBACK_SLOTS:
            logger.error(f"Invalid rollback slot: {slot}")
            return False

        rollback_src = ROLLBACK_DIR / slot

        if not list(rollback_src.glob("*.toml")):
            logger.error(f"Rollback slot {slot} is empty")
            return False

        # Copy rollback to shadow
        for f in SHADOW_DIR.glob("*.toml"):
            f.unlink()
        for f in rollback_src.glob("*.toml"):
            shutil.copy2(f, SHADOW_DIR / f.name)

        # Swap to apply rollback
        return self.swap()

    def _save_state(self, data: Dict[str, Any]):
        """Save state to state file"""
        STATE_FILE.write_text(json.dumps(data, indent=2))

    def drop_config(self, name: str, config: Dict[str, Any]) -> bool:
        """
        Convenience method: Drop a config and apply it

        This is the main entry point for droplet-style config updates.
        """
        with self.lock("drop_config") as lock:
            if not lock.acquired:
                logger.error("Failed to acquire lock for drop_config")
                return False

            # Write to shadow
            self.write_shadow(name, config)

            # Swap to active
            return self.swap()

    def drop_patch(self, patch_name: str, content: str) -> bool:
        """
        Convenience method: Drop a patch file and apply all pending
        """
        with self.lock("drop_patch") as lock:
            if not lock.acquired:
                logger.error("Failed to acquire lock for drop_patch")
                return False

            # Add patch
            self.add_patch(patch_name, content)

            # Apply all patches
            self.apply_patches()

            # Swap to active
            return self.swap()


# Singleton instance
_manager: Optional[ConfigManager] = None


def get_config_manager() -> ConfigManager:
    """Get singleton ConfigManager instance"""
    global _manager
    if _manager is None:
        _manager = ConfigManager()
    return _manager
