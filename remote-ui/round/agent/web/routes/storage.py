#!/usr/bin/env python3
"""
SecuBox Eye Remote - Storage Sync API Routes

FastAPI routes for storage management and config sync.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel
from typing import List, Optional
import base64

from ...sync import (
    get_storage_manager,
    get_backup_manager,
    get_config_sync,
    BackupType,
    SyncDirection,
)


router = APIRouter(prefix="/storage", tags=["storage"])


# Request/Response models
class StorageInfoResponse(BaseModel):
    """Storage information response."""
    image_path: str
    mount_path: str
    mounted: bool
    size_mb: float
    used_mb: float
    free_mb: float
    used_percent: float


class FileListResponse(BaseModel):
    """File listing response."""
    path: str
    files: List[dict]


class BackupRequest(BaseModel):
    """Backup creation request."""
    name: Optional[str] = None
    modules: Optional[List[str]] = None
    encrypt: bool = True
    backup_type: str = "full"


class BackupResponse(BaseModel):
    """Backup operation response."""
    success: bool
    message: str
    backup: Optional[dict] = None
    errors: List[str] = []


class RestoreRequest(BaseModel):
    """Restore request."""
    backup: str
    modules: Optional[List[str]] = None
    dry_run: bool = False


class ExportRequest(BaseModel):
    """Config export request."""
    modules: Optional[List[str]] = None


class ImportRequest(BaseModel):
    """Config import request."""
    modules: Optional[List[str]] = None
    validate: bool = True
    dry_run: bool = False


class SyncResultResponse(BaseModel):
    """Sync operation response."""
    status: str
    message: str
    synced_files: List[str] = []
    conflicts: List[str] = []
    errors: List[str] = []
    duration_ms: float = 0.0


class EncryptionKeyRequest(BaseModel):
    """Encryption key setting request."""
    key: str


# Storage endpoints
@router.get("/info", response_model=StorageInfoResponse)
async def get_storage_info():
    """Get storage information."""
    storage = get_storage_manager()
    info = storage.get_info()

    return StorageInfoResponse(
        image_path=info.image_path,
        mount_path=info.mount_path,
        mounted=info.mounted,
        size_mb=info.size_mb,
        used_mb=info.used_mb,
        free_mb=info.free_mb,
        used_percent=info.used_percent,
    )


@router.post("/mount")
async def mount_storage():
    """Mount the storage partition."""
    storage = get_storage_manager()

    if storage.mount():
        return {"status": "ok", "message": "Storage mounted"}
    else:
        raise HTTPException(status_code=500, detail="Failed to mount storage")


@router.post("/unmount")
async def unmount_storage():
    """Unmount the storage partition."""
    storage = get_storage_manager()

    if storage.unmount():
        return {"status": "ok", "message": "Storage unmounted"}
    else:
        raise HTTPException(status_code=500, detail="Failed to unmount storage")


@router.get("/files", response_model=FileListResponse)
async def list_files(path: str = ""):
    """List files in storage."""
    storage = get_storage_manager()

    if not storage.is_mounted:
        raise HTTPException(status_code=400, detail="Storage not mounted")

    files = storage.list_files(path)
    return FileListResponse(
        path=path,
        files=[f.to_dict() for f in files]
    )


@router.get("/file/{path:path}")
async def read_file(path: str):
    """Read a file from storage."""
    storage = get_storage_manager()

    if not storage.is_mounted:
        raise HTTPException(status_code=400, detail="Storage not mounted")

    content = storage.read_file(path)
    if content is None:
        raise HTTPException(status_code=404, detail="File not found")

    # Try to decode as text, fallback to base64
    try:
        text_content = content.decode("utf-8")
        return {"path": path, "content": text_content, "encoding": "utf-8"}
    except UnicodeDecodeError:
        return {
            "path": path,
            "content": base64.b64encode(content).decode(),
            "encoding": "base64"
        }


@router.put("/file/{path:path}")
async def write_file(path: str, file: UploadFile = File(...)):
    """Write a file to storage."""
    storage = get_storage_manager()

    if not storage.is_mounted:
        raise HTTPException(status_code=400, detail="Storage not mounted")

    content = await file.read()
    if storage.write_file(path, content, overwrite=True):
        return {"status": "ok", "path": path, "size": len(content)}
    else:
        raise HTTPException(status_code=500, detail="Failed to write file")


@router.delete("/file/{path:path}")
async def delete_file(path: str):
    """Delete a file from storage."""
    storage = get_storage_manager()

    if not storage.is_mounted:
        raise HTTPException(status_code=400, detail="Storage not mounted")

    if storage.delete_file(path):
        return {"status": "ok", "message": f"Deleted {path}"}
    else:
        raise HTTPException(status_code=500, detail="Failed to delete file")


# Backup endpoints
@router.get("/backups")
async def list_backups():
    """List all backups."""
    backup_manager = get_backup_manager()
    backups = backup_manager.list_backups()
    return {"backups": [b.to_dict() for b in backups]}


@router.post("/backup", response_model=BackupResponse)
async def create_backup(request: BackupRequest):
    """Create a new backup."""
    backup_manager = get_backup_manager()

    try:
        backup_type = BackupType(request.backup_type)
    except ValueError:
        backup_type = BackupType.FULL

    result = backup_manager.create_backup(
        name=request.name,
        modules=request.modules,
        encrypt=request.encrypt,
        backup_type=backup_type,
    )

    return BackupResponse(
        success=result.success,
        message=result.message,
        backup=result.backup_info.to_dict() if result.backup_info else None,
        errors=result.errors,
    )


@router.post("/restore", response_model=BackupResponse)
async def restore_backup(request: RestoreRequest):
    """Restore from a backup."""
    backup_manager = get_backup_manager()

    result = backup_manager.restore_backup(
        name=request.backup,
        modules=request.modules,
        dry_run=request.dry_run,
    )

    return BackupResponse(
        success=result.success,
        message=result.message,
        errors=result.errors,
    )


@router.delete("/backup/{name}")
async def delete_backup(name: str):
    """Delete a backup."""
    backup_manager = get_backup_manager()

    if backup_manager.delete_backup(name):
        return {"status": "ok", "message": f"Deleted backup {name}"}
    else:
        raise HTTPException(status_code=404, detail="Backup not found")


@router.post("/encryption-key")
async def set_encryption_key(request: EncryptionKeyRequest):
    """Set encryption key for backups."""
    backup_manager = get_backup_manager()
    backup_manager.set_encryption_key(request.key.encode())
    return {"status": "ok", "message": "Encryption key set"}


# Config sync endpoints
@router.post("/export", response_model=SyncResultResponse)
async def export_configs(request: ExportRequest):
    """Export configs from SecuBox to storage."""
    config_sync = get_config_sync()

    result = await config_sync.export_configs(modules=request.modules)

    return SyncResultResponse(
        status=result.status.value,
        message=result.message,
        synced_files=result.synced_files,
        conflicts=result.conflicts,
        errors=result.errors,
        duration_ms=result.duration_ms,
    )


@router.post("/import", response_model=SyncResultResponse)
async def import_configs(request: ImportRequest):
    """Import configs from storage to SecuBox."""
    config_sync = get_config_sync()

    result = await config_sync.import_configs(
        modules=request.modules,
        validate=request.validate,
        dry_run=request.dry_run,
    )

    return SyncResultResponse(
        status=result.status.value,
        message=result.message,
        synced_files=result.synced_files,
        conflicts=result.conflicts,
        errors=result.errors,
        duration_ms=result.duration_ms,
    )


@router.get("/sync-status")
async def get_sync_status(modules: Optional[str] = None):
    """Check sync status between local and remote."""
    config_sync = get_config_sync()

    module_list = modules.split(",") if modules else None
    status = await config_sync.check_sync_status(modules=module_list)

    return status


@router.get("/sync-history")
async def get_sync_history(limit: int = 20):
    """Get sync history."""
    config_sync = get_config_sync()
    history = config_sync.get_sync_history(limit=limit)
    return {"history": history}


@router.get("/audit-log")
async def get_audit_log(limit: int = 100):
    """Get storage audit log."""
    storage = get_storage_manager()
    log = storage.get_audit_log(limit=limit)
    return {"entries": log}
