"""secubox-gotosocial -- FastAPI application for GoToSocial Fediverse server management.

GoToSocial is an ActivityPub social network server.
Provides container management, account management, federation controls,
media storage, moderation tools, and emoji management.
"""
import asyncio
import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-gotosocial", version="1.0.0", root_path="/api/v1/gotosocial")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("gotosocial")

# Configuration
CONFIG_FILE = Path("/etc/secubox/gotosocial.toml")
CONTAINER_NAME = "secbx-gotosocial"
DATA_PATH_DEFAULT = "/srv/gotosocial"
DEFAULT_CONFIG = {
    "enabled": False,
    "image": "superseriousbusiness/gotosocial:latest",
    "port": 8080,
    "data_path": DATA_PATH_DEFAULT,
    "domain": "social.secubox.local",
    "account_domain": "",
    "haproxy": False,
    "registration_open": False,
    "approval_required": True,
    "email_verified_required": False,
    "instance_title": "SecuBox Social",
    "instance_description": "A SecuBox-powered GoToSocial instance",
    "instance_description_short": "SecuBox Social",
    "contact_email": "admin@secubox.local",
    "contact_account": "",
    "timezone": "Europe/Paris",
    "media_max_size": 40,
    "media_cleanup_days": 30,
    "federation_mode": "blocklist",
}


# ============================================================================
# Models
# ============================================================================

class GoToSocialConfig(BaseModel):
    enabled: bool = False
    image: str = "superseriousbusiness/gotosocial:latest"
    port: int = 8080
    data_path: str = DATA_PATH_DEFAULT
    domain: str = "social.secubox.local"
    account_domain: str = ""
    haproxy: bool = False
    registration_open: bool = False
    approval_required: bool = True
    email_verified_required: bool = False
    timezone: str = "Europe/Paris"


class InstanceSettings(BaseModel):
    instance_title: str = "SecuBox Social"
    instance_description: str = "A SecuBox-powered GoToSocial instance"
    instance_description_short: str = "SecuBox Social"
    contact_email: str = "admin@secubox.local"
    contact_account: str = ""
    registration_open: bool = False
    approval_required: bool = True


class AccountCreate(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    email: str
    password: str = Field(..., min_length=8)
    admin: bool = False


class FederationBlock(BaseModel):
    domain: str
    obfuscate: bool = False
    public_comment: str = ""
    private_comment: str = ""


class EmojiUpload(BaseModel):
    shortcode: str
    category: str = ""
    image_path: str


class MediaCleanup(BaseModel):
    days: int = 30
    dry_run: bool = True


# ============================================================================
# Helpers
# ============================================================================

def get_config() -> dict:
    """Load gotosocial configuration."""
    if CONFIG_FILE.exists():
        try:
            import tomllib
            return {**DEFAULT_CONFIG, **tomllib.loads(CONFIG_FILE.read_text())}
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save gotosocial configuration."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# GoToSocial configuration"]
    for k, v in config.items():
        if isinstance(v, bool):
            lines.append(f"{k} = {str(v).lower()}")
        elif isinstance(v, int):
            lines.append(f"{k} = {v}")
        elif isinstance(v, list):
            lines.append(f'{k} = {v}')
        else:
            lines.append(f'{k} = "{v}"')
    CONFIG_FILE.write_text("\n".join(lines) + "\n")


def detect_runtime() -> Optional[str]:
    """Detect container runtime."""
    if shutil.which("podman"):
        return "podman"
    if shutil.which("docker"):
        return "docker"
    return None


def get_container_status() -> dict:
    """Get GoToSocial container status."""
    rt = detect_runtime()
    if not rt:
        return {"status": "no_runtime", "uptime": ""}

    try:
        result = subprocess.run(
            [rt, "ps", "--filter", f"name={CONTAINER_NAME}", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip():
            return {"status": "running", "uptime": result.stdout.strip()}

        result = subprocess.run(
            [rt, "ps", "-a", "--filter", f"name={CONTAINER_NAME}", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip():
            return {"status": "stopped", "uptime": ""}

        return {"status": "not_installed", "uptime": ""}
    except Exception:
        return {"status": "error", "uptime": ""}


def is_running() -> bool:
    """Check if GoToSocial container is running."""
    return get_container_status()["status"] == "running"


def run_gts_cli(args: List[str], timeout: int = 30) -> dict:
    """Run gotosocial CLI command in container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    try:
        cmd = [rt, "exec", CONTAINER_NAME, "/gotosocial/gotosocial"] + args
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "success": result.returncode == 0,
            "output": result.stdout.strip(),
            "error": result.stderr.strip() if result.returncode != 0 else ""
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Public Endpoints
# ============================================================================

@router.get("/health")
async def health():
    """Health check."""
    return {"status": "ok", "module": "gotosocial"}


@router.get("/status")
async def status():
    """Get GoToSocial service status."""
    cfg = get_config()
    rt = detect_runtime()
    container = get_container_status()

    disk_usage = ""
    data_path = Path(cfg.get("data_path", DATA_PATH_DEFAULT))
    if data_path.exists():
        try:
            result = subprocess.run(
                ["du", "-sh", str(data_path)],
                capture_output=True, text=True, timeout=10
            )
            disk_usage = result.stdout.split()[0] if result.stdout else ""
        except Exception:
            pass

    # Get account/status counts if running
    users_count = 0
    statuses_count = 0
    if is_running():
        result = run_gts_cli(["admin", "account", "list"], timeout=10)
        if result["success"] and result.get("output"):
            users_count = len([l for l in result["output"].split("\n") if l.strip()])

    return {
        "enabled": cfg.get("enabled", False),
        "image": cfg.get("image", "superseriousbusiness/gotosocial:latest"),
        "port": cfg.get("port", 8080),
        "data_path": cfg.get("data_path", DATA_PATH_DEFAULT),
        "domain": cfg.get("domain", "social.secubox.local"),
        "account_domain": cfg.get("account_domain", ""),
        "haproxy": cfg.get("haproxy", False),
        "registration_open": cfg.get("registration_open", False),
        "approval_required": cfg.get("approval_required", True),
        "docker_available": rt is not None,
        "runtime": rt or "none",
        "container_status": container["status"],
        "container_uptime": container["uptime"],
        "disk_usage": disk_usage,
        "instance_title": cfg.get("instance_title", "SecuBox Social"),
        "federation_mode": cfg.get("federation_mode", "blocklist"),
        "users_count": users_count,
        "statuses_count": statuses_count,
    }


# ============================================================================
# Instance Management
# ============================================================================

@router.get("/instance")
async def get_instance_info(user=Depends(require_jwt)):
    """Get instance information."""
    cfg = get_config()
    return {
        "title": cfg.get("instance_title", "SecuBox Social"),
        "description": cfg.get("instance_description", ""),
        "description_short": cfg.get("instance_description_short", ""),
        "contact_email": cfg.get("contact_email", ""),
        "contact_account": cfg.get("contact_account", ""),
        "registration_open": cfg.get("registration_open", False),
        "approval_required": cfg.get("approval_required", True),
        "email_verified_required": cfg.get("email_verified_required", False),
        "domain": cfg.get("domain", "social.secubox.local"),
        "account_domain": cfg.get("account_domain", ""),
    }


@router.post("/instance")
async def update_instance_settings(settings: InstanceSettings, user=Depends(require_jwt)):
    """Update instance settings."""
    cfg = get_config()
    cfg["instance_title"] = settings.instance_title
    cfg["instance_description"] = settings.instance_description
    cfg["instance_description_short"] = settings.instance_description_short
    cfg["contact_email"] = settings.contact_email
    cfg["contact_account"] = settings.contact_account
    cfg["registration_open"] = settings.registration_open
    cfg["approval_required"] = settings.approval_required
    save_config(cfg)
    log.info(f"Instance settings updated by {user.get('sub', 'unknown')}")
    return {"success": True, "message": "Restart GoToSocial to apply changes"}


@router.get("/config")
async def get_gotosocial_config(user=Depends(require_jwt)):
    """Get GoToSocial configuration."""
    return get_config()


@router.post("/config")
async def set_gotosocial_config(config: GoToSocialConfig, user=Depends(require_jwt)):
    """Update GoToSocial configuration."""
    cfg = get_config()
    cfg.update(config.dict())
    save_config(cfg)
    log.info(f"Config updated by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Account Management
# ============================================================================

@router.get("/accounts")
async def list_accounts(user=Depends(require_jwt)):
    """List all local accounts."""
    if not is_running():
        return {"accounts": [], "error": "Container not running"}

    result = run_gts_cli(["admin", "account", "list"], timeout=15)
    if not result["success"]:
        return {"accounts": [], "error": result.get("error", "Failed to list accounts")}

    accounts = []
    lines = result.get("output", "").strip().split("\n")
    for line in lines:
        if line.strip() and not line.startswith("username"):
            parts = line.split()
            if parts:
                accounts.append({
                    "username": parts[0],
                    "email": parts[1] if len(parts) > 1 else "",
                    "suspended": "suspended" in line.lower(),
                    "admin": "admin" in line.lower() or "moderator" in line.lower(),
                })

    return {"accounts": accounts}


@router.post("/account")
async def create_account(account: AccountCreate, user=Depends(require_jwt)):
    """Create a new account."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    args = [
        "admin", "account", "create",
        "--username", account.username,
        "--email", account.email,
        "--password", account.password,
    ]

    result = run_gts_cli(args, timeout=30)
    if result["success"]:
        log.info(f"Account created: {account.username} by {user.get('sub', 'unknown')}")
        # Confirm the account
        run_gts_cli(["admin", "account", "confirm", "--username", account.username])
        if account.admin:
            run_gts_cli(["admin", "account", "promote", "--username", account.username])
    return result


@router.delete("/account/{username}")
async def delete_account(username: str, user=Depends(require_jwt)):
    """Delete an account (suspends it permanently)."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    result = run_gts_cli(["admin", "account", "suspend", "--username", username], timeout=60)
    if result["success"]:
        log.info(f"Account suspended/deleted: {username} by {user.get('sub', 'unknown')}")
    return result


@router.post("/account/{username}/suspend")
async def suspend_account(username: str, user=Depends(require_jwt)):
    """Suspend an account."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    result = run_gts_cli(["admin", "account", "suspend", "--username", username])
    if result["success"]:
        log.info(f"Account suspended: {username} by {user.get('sub', 'unknown')}")
    return result


@router.post("/account/{username}/unsuspend")
async def unsuspend_account(username: str, user=Depends(require_jwt)):
    """Unsuspend an account."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    result = run_gts_cli(["admin", "account", "unsuspend", "--username", username])
    if result["success"]:
        log.info(f"Account unsuspended: {username} by {user.get('sub', 'unknown')}")
    return result


@router.post("/account/{username}/confirm")
async def confirm_account(username: str, user=Depends(require_jwt)):
    """Confirm an account (approve signup)."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    result = run_gts_cli(["admin", "account", "confirm", "--username", username])
    if result["success"]:
        log.info(f"Account confirmed: {username} by {user.get('sub', 'unknown')}")
    return result


@router.post("/account/{username}/promote")
async def promote_account(username: str, user=Depends(require_jwt)):
    """Promote account to admin."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    result = run_gts_cli(["admin", "account", "promote", "--username", username])
    if result["success"]:
        log.info(f"Account promoted: {username} by {user.get('sub', 'unknown')}")
    return result


@router.post("/account/{username}/demote")
async def demote_account(username: str, user=Depends(require_jwt)):
    """Demote account from admin."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    result = run_gts_cli(["admin", "account", "demote", "--username", username])
    if result["success"]:
        log.info(f"Account demoted: {username} by {user.get('sub', 'unknown')}")
    return result


@router.post("/account/{username}/password")
async def reset_password(username: str, user=Depends(require_jwt)):
    """Reset account password (generates new one)."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    result = run_gts_cli(["admin", "account", "password", "--username", username])
    if result["success"]:
        log.info(f"Password reset for: {username} by {user.get('sub', 'unknown')}")
    return result


# ============================================================================
# Federation Management
# ============================================================================

@router.get("/federation/peers")
async def get_federation_peers(user=Depends(require_jwt)):
    """Get list of federated instances."""
    if not is_running():
        return {"blocked": [], "allowed": [], "error": "Container not running"}

    blocks_result = run_gts_cli(["admin", "domain", "block", "list"], timeout=15)
    blocked_domains = []
    if blocks_result["success"] and blocks_result.get("output"):
        blocked_domains = [d.strip() for d in blocks_result["output"].split("\n") if d.strip()]

    allows_result = run_gts_cli(["admin", "domain", "allow", "list"], timeout=15)
    allowed_domains = []
    if allows_result["success"] and allows_result.get("output"):
        allowed_domains = [d.strip() for d in allows_result["output"].split("\n") if d.strip()]

    cfg = get_config()
    return {
        "federation_mode": cfg.get("federation_mode", "blocklist"),
        "blocked": blocked_domains,
        "allowed": allowed_domains,
    }


@router.post("/federation/block")
async def block_domain(block: FederationBlock, user=Depends(require_jwt)):
    """Block a federated domain."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    args = ["admin", "domain", "block", "create", "--domain", block.domain]
    if block.obfuscate:
        args.append("--obfuscate")
    if block.public_comment:
        args.extend(["--public-comment", block.public_comment])
    if block.private_comment:
        args.extend(["--private-comment", block.private_comment])

    result = run_gts_cli(args)
    if result["success"]:
        log.info(f"Domain blocked: {block.domain} by {user.get('sub', 'unknown')}")
    return result


@router.delete("/federation/block/{domain}")
async def unblock_domain(domain: str, user=Depends(require_jwt)):
    """Unblock a federated domain."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    result = run_gts_cli(["admin", "domain", "block", "delete", "--domain", domain])
    if result["success"]:
        log.info(f"Domain unblocked: {domain} by {user.get('sub', 'unknown')}")
    return result


@router.post("/federation/allow")
async def allow_domain(domain: str = Query(...), user=Depends(require_jwt)):
    """Add domain to allowlist."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    result = run_gts_cli(["admin", "domain", "allow", "create", "--domain", domain])
    if result["success"]:
        log.info(f"Domain allowed: {domain} by {user.get('sub', 'unknown')}")
    return result


@router.delete("/federation/allow/{domain}")
async def remove_allowed_domain(domain: str, user=Depends(require_jwt)):
    """Remove domain from allowlist."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    result = run_gts_cli(["admin", "domain", "allow", "delete", "--domain", domain])
    if result["success"]:
        log.info(f"Domain removed from allowlist: {domain} by {user.get('sub', 'unknown')}")
    return result


# ============================================================================
# Media Management
# ============================================================================

@router.get("/media/stats")
async def get_media_stats(user=Depends(require_jwt)):
    """Get media storage statistics."""
    cfg = get_config()
    data_path = Path(cfg.get("data_path", DATA_PATH_DEFAULT))
    storage_path = data_path / "storage"

    stats = {
        "total_size": "0",
        "local_media": "0",
        "remote_cache": "0",
        "emoji_count": 0,
        "attachment_count": 0,
    }

    if storage_path.exists():
        try:
            result = subprocess.run(
                ["du", "-sh", str(storage_path)],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                stats["total_size"] = result.stdout.split()[0]

            attachments_path = storage_path / "attachments"
            if attachments_path.exists():
                result = subprocess.run(
                    ["find", str(attachments_path), "-type", "f"],
                    capture_output=True, text=True, timeout=60
                )
                stats["attachment_count"] = len(result.stdout.strip().split("\n")) if result.stdout.strip() else 0

            emojis_path = storage_path / "emoji"
            if emojis_path.exists():
                result = subprocess.run(
                    ["find", str(emojis_path), "-type", "f"],
                    capture_output=True, text=True, timeout=30
                )
                stats["emoji_count"] = len(result.stdout.strip().split("\n")) if result.stdout.strip() else 0

        except Exception as e:
            stats["error"] = str(e)

    return stats


@router.post("/media/cleanup")
async def cleanup_media(cleanup: MediaCleanup, user=Depends(require_jwt)):
    """Clean up unused remote media cache."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    args = ["admin", "media", "prune", "remote", "--days", str(cleanup.days)]
    if cleanup.dry_run:
        args.append("--dry-run")

    result = run_gts_cli(args, timeout=300)
    if result["success"]:
        log.info(f"Media cleanup executed by {user.get('sub', 'unknown')}: dry_run={cleanup.dry_run}")
    return result


@router.post("/media/prune/orphaned")
async def prune_orphaned_media(user=Depends(require_jwt)):
    """Prune orphaned media attachments."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    result = run_gts_cli(["admin", "media", "prune", "orphaned"], timeout=300)
    if result["success"]:
        log.info(f"Orphaned media pruned by {user.get('sub', 'unknown')}")
    return result


# ============================================================================
# Emoji Management
# ============================================================================

@router.get("/emojis")
async def list_emojis(user=Depends(require_jwt)):
    """List custom emojis."""
    if not is_running():
        return {"emojis": [], "error": "Container not running"}

    result = run_gts_cli(["admin", "emoji", "list", "local"], timeout=15)
    if not result["success"]:
        return {"emojis": [], "error": result.get("error", "Failed to list emojis")}

    emojis = []
    lines = result.get("output", "").strip().split("\n")
    for line in lines:
        if line.strip() and not line.startswith("shortcode"):
            parts = line.split()
            if parts:
                emojis.append({
                    "shortcode": parts[0].replace(":", ""),
                    "category": parts[1] if len(parts) > 1 else "",
                    "url": ""
                })

    return {"emojis": emojis}


@router.post("/emoji")
async def upload_emoji(emoji: EmojiUpload, user=Depends(require_jwt)):
    """Upload a custom emoji."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    if not Path(emoji.image_path).exists():
        return {"success": False, "error": "Image file not found"}

    args = [
        "admin", "emoji", "create",
        "--shortcode", emoji.shortcode,
        "--path", emoji.image_path,
    ]
    if emoji.category:
        args.extend(["--category", emoji.category])

    result = run_gts_cli(args, timeout=30)
    if result["success"]:
        log.info(f"Emoji uploaded: {emoji.shortcode} by {user.get('sub', 'unknown')}")
    return result


@router.delete("/emoji/{shortcode}")
async def delete_emoji(shortcode: str, user=Depends(require_jwt)):
    """Delete a custom emoji."""
    if not is_running():
        return {"success": False, "error": "Container not running"}

    result = run_gts_cli(["admin", "emoji", "delete", "--shortcode", shortcode])
    if result["success"]:
        log.info(f"Emoji deleted: {shortcode} by {user.get('sub', 'unknown')}")
    return result


# ============================================================================
# Moderation / Reports
# ============================================================================

@router.get("/reports")
async def list_reports(resolved: bool = False, user=Depends(require_jwt)):
    """List moderation reports."""
    if not is_running():
        return {"reports": [], "error": "Container not running"}

    return {
        "reports": [],
        "note": "Reports management via GoToSocial admin panel"
    }


# ============================================================================
# Container Management
# ============================================================================

@router.get("/container/status")
async def container_status(user=Depends(require_jwt)):
    """Get container status details."""
    rt = detect_runtime()
    if not rt:
        return {"status": "no_runtime", "runtime": None}

    container = get_container_status()
    cfg = get_config()

    image_info = ""
    if container["status"] != "not_installed":
        try:
            result = subprocess.run(
                [rt, "inspect", CONTAINER_NAME, "--format", "{{.Config.Image}}"],
                capture_output=True, text=True, timeout=5
            )
            image_info = result.stdout.strip()
        except Exception:
            pass

    return {
        "runtime": rt,
        "container_name": CONTAINER_NAME,
        "status": container["status"],
        "uptime": container["uptime"],
        "image": image_info or cfg.get("image", ""),
        "port": cfg.get("port", 8080),
    }


@router.post("/container/install")
async def install_gotosocial(user=Depends(require_jwt)):
    """Install GoToSocial container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime (docker/podman) found"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", DATA_PATH_DEFAULT))

    data_path.mkdir(parents=True, exist_ok=True)
    (data_path / "storage").mkdir(exist_ok=True)

    image = cfg.get("image", "superseriousbusiness/gotosocial:latest")
    log.info(f"Installing GoToSocial ({image}) by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(
            [rt, "pull", image],
            capture_output=True, text=True, timeout=600
        )
        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip(), "output": result.stdout}

        return {"success": True, "output": "Image pulled successfully"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Pull timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/start")
async def start_gotosocial(user=Depends(require_jwt)):
    """Start GoToSocial container."""
    if is_running():
        return {"success": False, "error": "Already running"}

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", DATA_PATH_DEFAULT))
    port = cfg.get("port", 8080)
    image = cfg.get("image", "superseriousbusiness/gotosocial:latest")
    domain = cfg.get("domain", "social.secubox.local")
    account_domain = cfg.get("account_domain", "") or domain
    tz = cfg.get("timezone", "Europe/Paris")

    data_path.mkdir(parents=True, exist_ok=True)
    (data_path / "storage").mkdir(exist_ok=True)

    cmd = [
        rt, "run", "-d",
        "--name", CONTAINER_NAME,
        "-v", f"{data_path}:/gotosocial/storage",
        "-e", f"TZ={tz}",
        "-e", f"GTS_HOST={domain}",
        "-e", f"GTS_ACCOUNT_DOMAIN={account_domain}",
        "-e", f"GTS_PROTOCOL=https",
        "-e", f"GTS_PORT=8080",
        "-e", f"GTS_BIND_ADDRESS=0.0.0.0",
        "-e", f"GTS_DB_TYPE=sqlite",
        "-e", f"GTS_DB_ADDRESS=/gotosocial/storage/sqlite.db",
        "-e", f"GTS_STORAGE_LOCAL_BASE_PATH=/gotosocial/storage",
        "-e", f"GTS_LETSENCRYPT_ENABLED=false",
        "-e", f"GTS_ACCOUNTS_REGISTRATION_OPEN={str(cfg.get('registration_open', False)).lower()}",
        "-e", f"GTS_ACCOUNTS_APPROVAL_REQUIRED={str(cfg.get('approval_required', True)).lower()}",
        "-e", f"GTS_INSTANCE_EXPOSE_PUBLIC_TIMELINE=true",
        "-p", f"127.0.0.1:{port}:8080",
        "--restart", "unless-stopped",
    ]

    cmd.append(image)

    log.info(f"Starting GoToSocial by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "rm", "-f", CONTAINER_NAME], capture_output=True, timeout=10)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        await asyncio.sleep(5)

        if is_running():
            return {"success": True}
        else:
            return {"success": False, "error": result.stderr.strip() or "Failed to start"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/stop")
async def stop_gotosocial(user=Depends(require_jwt)):
    """Stop GoToSocial container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    log.info(f"Stopping GoToSocial by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "stop", CONTAINER_NAME], capture_output=True, timeout=30)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/restart")
async def restart_gotosocial(user=Depends(require_jwt)):
    """Restart GoToSocial container."""
    await stop_gotosocial(user)
    await asyncio.sleep(2)
    return await start_gotosocial(user)


@router.post("/container/update")
async def update_gotosocial(user=Depends(require_jwt)):
    """Update GoToSocial to latest image."""
    cfg = get_config()
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    image = cfg.get("image", "superseriousbusiness/gotosocial:latest")
    log.info(f"Updating GoToSocial ({image}) by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(
            [rt, "pull", image],
            capture_output=True, text=True, timeout=600
        )
        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip()}

        if is_running():
            await restart_gotosocial(user)

        return {"success": True, "output": "Update complete"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/uninstall")
async def uninstall_gotosocial(user=Depends(require_jwt)):
    """Uninstall GoToSocial container (preserves data)."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    log.info(f"Uninstalling GoToSocial by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "stop", CONTAINER_NAME], capture_output=True, timeout=30)
        subprocess.run([rt, "rm", "-f", CONTAINER_NAME], capture_output=True, timeout=10)
        return {"success": True, "message": "Container removed, data preserved"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Backup
# ============================================================================

@router.post("/backup")
async def create_backup(user=Depends(require_jwt)):
    """Create a backup of GoToSocial data."""
    cfg = get_config()
    data_path = Path(cfg.get("data_path", DATA_PATH_DEFAULT))

    if not data_path.exists():
        return {"success": False, "error": "No data to backup"}

    backup_dir = Path("/var/lib/secubox/backups/gotosocial")
    backup_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_file = backup_dir / f"gotosocial-backup-{timestamp}.tar.gz"

    log.info(f"Creating backup by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(
            ["tar", "-czf", str(backup_file), "-C", str(data_path.parent), data_path.name],
            capture_output=True, text=True, timeout=600
        )
        if result.returncode == 0:
            size = backup_file.stat().st_size / 1024 / 1024
            return {"success": True, "path": str(backup_file), "size": f"{size:.1f} MB"}
        else:
            return {"success": False, "error": result.stderr.strip()}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Logs
# ============================================================================

@router.get("/logs")
async def get_logs(lines: int = 100, user=Depends(require_jwt)):
    """Get container logs."""
    rt = detect_runtime()
    if not rt:
        return {"logs": "No container runtime"}

    try:
        result = subprocess.run(
            [rt, "logs", "--tail", str(min(lines, 500)), CONTAINER_NAME],
            capture_output=True, text=True, timeout=10
        )
        logs = result.stdout + result.stderr
        return {"logs": logs}
    except Exception:
        return {"logs": "No logs available"}


app.include_router(router)
