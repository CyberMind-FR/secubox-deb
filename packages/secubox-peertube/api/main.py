"""secubox-peertube -- FastAPI application for PeerTube video platform management.

PeerTube runs NATIVELY inside a dedicated Debian LXC (peertube.service:
Node 22 + PostgreSQL 15 + Redis + ffmpeg), provisioned by
`peertubectl install` / lib/peertube/install-lxc.sh. This dashboard talks to
that instance over HTTP at <lxc_ip>:<http_port> and drives the LXC lifecycle
via peertubectl. It is NOT a Docker/Podman manager.

SecuBox-Deb :: PeerTube
CyberMind -- https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
import asyncio
import json
import os
import re
import secrets
import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Optional, Dict

from fastapi import FastAPI, APIRouter, Depends, Request, HTTPException
from pydantic import BaseModel, Field

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core import user_store
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-peertube", version="1.1.0", root_path="/api/v1/peertube")

# ══════════════════════════════════════════════════════════════════
# Health Check Endpoint (public, no auth)
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Public health check endpoint for sidebar status."""
    return {"status": "ok", "module": "deb"}

app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("peertube")

# Configuration
CONFIG_FILE = Path("/etc/secubox/peertube.toml")
INSTALL_LIB = "/usr/share/secubox/lib/peertube/install-lxc.sh"
PEERTUBECTL = "/usr/sbin/peertubectl"

# Flat defaults. The on-disk TOML uses [lxc]/[peertube]/[exposure] sections;
# get_config() flattens them into these keys.
DEFAULT_CONFIG = {
    # LXC
    "name": "peertube",
    "ip": "10.100.0.120",
    "path": "/data/lxc",
    "data_path": "/data/peertube",
    # PeerTube (inside the LXC)
    "http_port": 9000,
    "admin_user": "root",
    "admin_password_file": "/etc/secubox/secrets/peertube-admin",
    "transcoding_enabled": True,
    "transcoding_threads": 2,
    "hls_enabled": True,
    "webtorrent_enabled": True,
    "federation_enabled": True,
    "instance_name": "SecuBox PeerTube",
    "short_description": "Federated video platform on SecuBox",
    # Exposure
    "public_hostname": "peertube.gk2.secubox.in",
}


# ============================================================================
# Models
# ============================================================================

class PeerTubeConfig(BaseModel):
    http_port: int = 9000
    public_hostname: str = "peertube.gk2.secubox.in"
    transcoding_enabled: bool = True
    transcoding_threads: int = 2
    hls_enabled: bool = True
    webtorrent_enabled: bool = True
    federation_enabled: bool = True


class InstanceSettings(BaseModel):
    name: str = "SecuBox PeerTube"
    short_description: str = "Video hosting on SecuBox"
    description: str = ""
    terms: str = ""
    signup_enabled: bool = False
    signup_requires_email: bool = True


class ChannelCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    display_name: str = Field(..., min_length=1, max_length=100)
    description: str = ""


class UserCreate(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    email: str
    password: str = Field(..., min_length=8)
    role: int = 2  # 0=admin, 1=moderator, 2=user
    video_quota: int = -1  # -1 = unlimited


class FollowRequest(BaseModel):
    hosts: List[str]


class TranscodingSettings(BaseModel):
    enabled: bool = True
    threads: int = 2
    hls_enabled: bool = True
    webtorrent_enabled: bool = True
    resolutions: Dict[str, bool] = {
        "240p": True, "360p": True, "480p": True, "720p": True,
        "1080p": True, "1440p": False, "2160p": False,
    }


class PluginInstall(BaseModel):
    npm_name: str  # e.g., peertube-plugin-auth-ldap


class ResetPasswordBody(BaseModel):
    password: Optional[str] = None


class VideoImport(BaseModel):
    """Import a video from a remote URL (YouTube, Vimeo, direct .mp4, …).

    Uses PeerTube's native HTTP import (yt-dlp under the hood)."""
    target_url: str = Field(..., min_length=4)
    channel_id: Optional[int] = None      # default channel if omitted
    name: Optional[str] = None            # title; PeerTube derives one if omitted
    privacy: int = 1                      # 1=public 2=unlisted 3=private 4=internal


class PlaylistImport(BaseModel):
    """Import every video of a playlist/channel/showcase URL (#981).

    Each video still goes through PeerTube's own native HTTP import one at a
    time — see _process_playlist_job for why this is sequential, never fired
    all at once."""
    target_url: str = Field(..., min_length=4)
    channel_id: Optional[int] = None
    name_prefix: Optional[str] = None     # prefixed to each video's own title
    privacy: int = 1                      # 1=public 2=unlisted 3=private 4=internal


# ============================================================================
# Config helpers
# ============================================================================

def get_config() -> dict:
    """Load + flatten peertube.toml ([lxc]/[peertube]/[exposure]) over defaults."""
    cfg = DEFAULT_CONFIG.copy()
    if CONFIG_FILE.exists():
        try:
            import tomllib
            raw = tomllib.loads(CONFIG_FILE.read_text())
            for section in ("lxc", "peertube", "exposure"):
                for k, v in (raw.get(section) or {}).items():
                    cfg[k] = v
            for k, v in raw.items():        # tolerate flat keys too
                if not isinstance(v, dict):
                    cfg[k] = v
        except Exception:
            pass
    return cfg


def save_config(config: dict):
    """Persist a flat config back as sectioned TOML."""
    cfg = config
    lxc_keys = ("name", "ip", "gateway", "bridge", "path", "debian_suite")
    pt_keys = ("http_port", "admin_user", "admin_password_file", "secret_file",
               "admin_email", "transcoding_enabled", "transcoding_threads",
               "hls_enabled", "webtorrent_enabled", "federation_enabled",
               "instance_name", "short_description", "description", "terms",
               "signup_enabled", "signup_requires_email", "transcoding_resolutions")
    exp_keys = ("public_hostname", "waf_inspect")

    def emit(k):
        v = cfg.get(k)
        if v is None:
            return None
        if isinstance(v, bool):
            return f"{k} = {str(v).lower()}"
        if isinstance(v, int):
            return f"{k} = {v}"
        if isinstance(v, (dict, list)):
            return f"{k} = {json.dumps(v)}"
        return f'{k} = "{v}"'

    out = ["# /etc/secubox/peertube.toml — managed by secubox-peertube"]
    for section, keys in (("lxc", lxc_keys), ("peertube", pt_keys), ("exposure", exp_keys)):
        rows = [emit(k) for k in keys if k in cfg and emit(k) is not None]
        if rows:
            out.append(f"\n[{section}]")
            out.extend(rows)
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text("\n".join(out) + "\n")


# ============================================================================
# Native-LXC + PeerTube HTTP helpers
# ============================================================================

def get_lxc_state() -> str:
    """LXC container state: running | stopped | absent."""
    cfg = get_config()
    try:
        r = subprocess.run(
            ["lxc-info", "-n", cfg["name"], "-P", cfg["path"]],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            if line.strip().lower().startswith("state:"):
                return line.split(":", 1)[1].strip().lower()
        return "absent"
    except Exception:
        return "absent"


def http_reachable() -> bool:
    """True if PeerTube answers on <ip>:<http_port>."""
    cfg = get_config()
    url = f"http://{cfg['ip']}:{cfg['http_port']}/api/v1/config"
    try:
        r = subprocess.run(
            ["curl", "-fsS", "-o", "/dev/null", "--max-time", "3",
             "-H", f"Host: {cfg['public_hostname']}", url],
            capture_output=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def is_running() -> bool:
    return http_reachable()


def pt_api(endpoint: str, method: str = "GET", data: Optional[dict] = None,
           token: Optional[str] = None, timeout: int = 20) -> dict:
    """Call PeerTube's HTTP API at <ip>:<http_port>.

    PeerTube rejects requests whose Host is the raw IP, so we always send
    Host: <public_hostname> (the configured webserver hostname)."""
    cfg = get_config()
    base = f"http://{cfg['ip']}:{cfg['http_port']}/api/v1"
    cmd = ["curl", "-s", "--max-time", str(timeout),
           "-H", f"Host: {cfg['public_hostname']}", base + endpoint]
    if token:
        cmd += ["-H", f"Authorization: Bearer {token}"]
    if method == "POST":
        cmd += ["-X", "POST"]
        if data is not None:
            cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(data)]
    elif method == "DELETE":
        cmd += ["-X", "DELETE"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        if r.returncode == 0 and r.stdout:
            try:
                return {"success": True, "data": json.loads(r.stdout)}
            except json.JSONDecodeError:
                return {"success": True, "data": r.stdout}
        return {"success": False, "error": r.stderr.strip() or "API call failed"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "API timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_admin_token() -> Optional[str]:
    """OAuth password-grant token for the stored admin user (for write ops)."""
    cfg = get_config()
    pw_file = Path(cfg.get("admin_password_file", "/etc/secubox/secrets/peertube-admin"))
    if not pw_file.exists():
        return None
    password = pw_file.read_text().strip()
    username = cfg.get("admin_user", "root")
    oc = pt_api("/oauth-clients/local")
    if not oc.get("success") or not isinstance(oc.get("data"), dict):
        return None
    client = oc["data"]
    base = f"http://{cfg['ip']}:{cfg['http_port']}/api/v1/users/token"
    cmd = ["curl", "-s", "--max-time", "15", "-H", f"Host: {cfg['public_hostname']}", base,
           "-d", f"client_id={client.get('client_id','')}",
           "-d", f"client_secret={client.get('client_secret','')}",
           "-d", "grant_type=password",
           "-d", f"username={username}",
           "-d", f"password={password}"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        tok = json.loads(r.stdout)
        return tok.get("access_token")
    except Exception:
        return None


def default_channel_id(token: str) -> Optional[int]:
    me = pt_api("/users/me", token=token)
    if me.get("success") and isinstance(me.get("data"), dict):
        chans = me["data"].get("videoChannels") or []
        if chans:
            return chans[0].get("id")
    return None


# ============================================================================
# Admin Ops Spool Plumbing (issue #798)
# ============================================================================

OPS_DIR = Path("/run/secubox/peertube/ops")
# Results live in a separate dir from requests so the root peertube-ops.path
# (DirectoryNotEmpty= on OPS_DIR) isn't re-triggered by a lingering result (#798).
RESULTS_DIR = Path("/run/secubox/peertube/results")
_OP_ID_RE = re.compile(r"^[0-9a-f]{8,32}$")


async def require_admin(user=Depends(require_jwt)):
    """Gate destructive ops to admin-role identities. require_jwt validated the
    token; the role lives in the user store (JWT carries only sub/jti), so look
    it up like auth.py's verify handler does."""
    sub = (user or {}).get("sub") if isinstance(user, dict) else None
    role = ""
    try:
        u = user_store.get_user(sub) or {}
        role = u.get("role", "") if isinstance(u, dict) else ""
    except Exception:
        role = ""
    if role != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    return user


def _spool_op(op: str, **args) -> str:
    """Write an intent file the root peertube-ops.path unit will pick up. Returns
    the op id; the caller polls GET /admin/op/{id}. Unprivileged (no lxc-attach)."""
    op_id = secrets.token_hex(8)
    OPS_DIR.mkdir(parents=True, exist_ok=True)
    req = OPS_DIR / f"{op_id}.request.json"
    fd = os.open(str(req), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, json.dumps({"op": op, "id": op_id, **args}).encode())
    os.close(fd)
    return op_id


def _read_op_result(op_id: str) -> dict:
    """Read <id>.result.json; {status: pending} until the root unit writes it."""
    if not _OP_ID_RE.match(op_id or ""):
        return {"status": "error", "detail": "bad op id"}
    res = RESULTS_DIR / f"{op_id}.result.json"
    if not res.exists():
        return {"status": "pending"}
    try:
        return json.loads(res.read_text())
    except Exception as e:  # pragma: no cover
        return {"status": "error", "detail": f"unreadable result: {e}"}


# ============================================================================
# Public Endpoints
# ============================================================================

@router.get("/health")
async def health():
    return {"status": "ok", "module": "peertube"}


@router.get("/status")
def status():
    """Real native-LXC status: LXC state + PeerTube HTTP reachability + disk."""
    cfg = get_config()
    state = get_lxc_state()
    reachable = http_reachable()

    disk_usage = ""
    data_path = Path(cfg.get("data_path", "/data/peertube"))
    if data_path.exists():
        try:
            r = subprocess.run(["du", "-sh", str(data_path)],
                               capture_output=True, text=True, timeout=30)
            disk_usage = r.stdout.split()[0] if r.stdout else ""
        except Exception:
            pass

    # Live counts straight from the instance config/stats when reachable.
    instance_name = cfg.get("instance_name", "SecuBox PeerTube")
    server_version = ""
    video_count = 0
    if reachable:
        c = pt_api("/config")
        if c.get("success") and isinstance(c.get("data"), dict):
            d = c["data"]
            instance_name = (d.get("instance") or {}).get("name", instance_name)
            server_version = d.get("serverVersion", "")
        v = pt_api("/videos?count=0")
        if v.get("success") and isinstance(v.get("data"), dict):
            video_count = v["data"].get("total", 0)

    # Map LXC state onto the keys the webui already consumes. The dashboard
    # runs as the unprivileged 'secubox' user, which can't always read the
    # root-owned LXC via lxc-info (reports "absent"); trust HTTP reachability
    # as the primary "running" signal, fall back to lxc_state when unreachable.
    if reachable:
        container_status = "running"
    else:
        container_status = {"running": "running", "stopped": "stopped",
                            "absent": "not_installed"}.get(state, state)

    return {
        "deployment": "lxc-native",
        "lxc_name": cfg.get("name", "peertube"),
        "lxc_ip": cfg.get("ip", "10.100.0.120"),
        "lxc_state": state,
        "http_port": cfg.get("http_port", 9000),
        "http_reachable": reachable,
        "data_path": cfg.get("data_path", "/data/peertube"),
        "domain": cfg.get("public_hostname", "peertube.gk2.secubox.in"),
        "public_url": f"https://{cfg.get('public_hostname', 'peertube.gk2.secubox.in')}/",
        "transcoding_enabled": cfg.get("transcoding_enabled", True),
        "federation_enabled": cfg.get("federation_enabled", True),
        # webui back-compat keys (was Docker; now native-LXC):
        "runtime": "lxc-native",
        "container_status": container_status,
        "container_uptime": "",
        "disk_usage": disk_usage,
        "video_count": video_count,
        "instance_name": instance_name,
        "server_version": server_version,
    }


# ============================================================================
# Instance Management
# ============================================================================

@router.get("/instance")
async def get_instance(user=Depends(require_jwt)):
    cfg = get_config()
    return {
        "name": cfg.get("instance_name", "SecuBox PeerTube"),
        "short_description": cfg.get("short_description", "Video hosting on SecuBox"),
        "description": cfg.get("description", ""),
        "terms": cfg.get("terms", ""),
        "signup_enabled": cfg.get("signup_enabled", False),
        "signup_requires_email": cfg.get("signup_requires_email", True),
        "domain": cfg.get("public_hostname", "peertube.gk2.secubox.in"),
    }


@router.post("/instance")
async def update_instance(settings: InstanceSettings, user=Depends(require_jwt)):
    cfg = get_config()
    cfg["instance_name"] = settings.name
    cfg["short_description"] = settings.short_description
    cfg["description"] = settings.description
    cfg["terms"] = settings.terms
    cfg["signup_enabled"] = settings.signup_enabled
    cfg["signup_requires_email"] = settings.signup_requires_email
    save_config(cfg)
    log.info(f"Instance settings updated by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Video Management
# ============================================================================

@router.get("/videos")
async def list_videos(start: int = 0, count: int = 15,
                      sort: str = "-publishedAt", user=Depends(require_jwt)):
    if not is_running():
        return {"videos": [], "total": 0, "error": "PeerTube not reachable"}
    result = pt_api(f"/videos?start={start}&count={count}&sort={sort}")
    if result.get("success") and isinstance(result.get("data"), dict):
        d = result["data"]
        return {"videos": d.get("data", []), "total": d.get("total", 0)}
    return {"videos": [], "total": 0}


@router.delete("/video/{video_id}")
async def delete_video(video_id: str, user=Depends(require_jwt)):
    if not is_running():
        return {"success": False, "error": "PeerTube not reachable"}
    token = get_admin_token()
    log.info(f"Deleting video {video_id} by {user.get('sub', 'unknown')}")
    result = pt_api(f"/videos/{video_id}", method="DELETE", token=token)
    return {"success": result.get("success", False)}


# ============================================================================
# Video Import (yt-dlp via PeerTube native HTTP import)
# ============================================================================

@router.get("/imports")
async def list_imports(user=Depends(require_jwt)):
    """List the current user's video imports (queued/processing/done/failed)."""
    if not is_running():
        return {"imports": [], "total": 0, "error": "PeerTube not reachable"}
    token = get_admin_token()
    if not token:
        return {"imports": [], "total": 0, "error": "no admin credentials on host"}
    result = pt_api("/users/me/videos/imports?count=20&sort=-createdAt", token=token)
    if result.get("success") and isinstance(result.get("data"), dict):
        d = result["data"]
        return {"imports": d.get("data", []), "total": d.get("total", 0)}
    return {"imports": [], "total": 0, "error": result.get("error", "import list failed")}


async def _submit_import(target_url: str, channel_id: Optional[int], privacy: int,
                          name: Optional[str], token: str) -> dict:
    """POST /videos/imports for ONE video. The actual curl call is blocking
    (pt_api uses subprocess.run), so it is offloaded to a worker thread —
    this helper is also called in a loop from the playlist worker, which
    would otherwise stall the whole event loop for as long as a playlist
    takes to process (CLAUDE.md: never block the loop)."""
    payload = {"targetUrl": target_url, "channelId": channel_id, "privacy": privacy}
    if name:
        payload["name"] = name
    result = await asyncio.to_thread(pt_api, "/videos/imports", "POST", payload, token, 60)
    if result.get("success"):
        d = result.get("data") or {}
        vid = (d.get("video") or {})
        return {"success": True, "import_id": d.get("id"),
                "video_uuid": vid.get("uuid"), "state": (d.get("state") or {})}
    return {"success": False, "error": result.get("error", "import failed")}


@router.post("/import")
async def import_video(req: VideoImport, user=Depends(require_jwt)):
    """Download a video from a URL into PeerTube (yt-dlp under the hood).

    PeerTube must have import.videos.http enabled (install-lxc.sh sets it)."""
    if not is_running():
        return {"success": False, "error": "PeerTube not reachable"}
    token = get_admin_token()
    if not token:
        return {"success": False,
                "error": "No admin credentials at /etc/secubox/secrets/peertube-admin"}
    channel_id = req.channel_id or default_channel_id(token)
    if not channel_id:
        return {"success": False, "error": "could not resolve a target channel"}
    log.info(f"Importing {req.target_url} → channel {channel_id} by {user.get('sub', 'unknown')}")
    return await _submit_import(req.target_url, channel_id, req.privacy, req.name, token)


# ============================================================================
# Playlist Import (#981) — expand a playlist/channel URL into N single-video
# native imports, submitted ONE AT A TIME.
#
# PeerTube's native HTTP import only ever takes one video per call; there is
# no upstream "import a whole playlist" endpoint. Expansion happens HOST-side
# with a metadata-only `yt-dlp --flat-playlist` probe (no download — the
# actual fetch + the fixed H.264/AAC format selection still happen entirely
# inside PeerTube's own import job, untouched by this module).
#
# Concurrency bound: the worker below AWAITS each submitted import reaching a
# terminal PeerTube state before submitting the next — for both items of one
# job AND across every queued playlist job (one global worker/queue). That
# guarantees at most one playlist-triggered yt-dlp/ffmpeg pipeline is ever
# running at a time, regardless of playlist size or how many playlists are
# queued — the board's load already swings 45-101 (see CLAUDE.md), so this is
# the conservative choice: correctness and a hard cap over throughput.
# ============================================================================

YTDLP_BIN = "yt-dlp"
PLAYLIST_JOBS_FILE = Path("/var/lib/secubox/peertube/playlist-jobs.json")
PLAYLIST_PROBE_TIMEOUT = 90     # seconds — metadata-only, no download
PLAYLIST_ITEM_TIMEOUT = 1800    # seconds — ceiling per video (fetch + transcode)
PLAYLIST_POLL_INTERVAL = 5      # seconds between import-state polls

_playlist_jobs: Dict[str, dict] = {}
_playlist_queue: Optional["asyncio.Queue[str]"] = None
_playlist_worker_task = None

_TERMINAL_IMPORT_LABELS = {"success", "failed", "rejected", "cancelled", "canceled"}

# Playlist-shaped URL syntax across the sites yt-dlp commonly sees here
# (YouTube list=/playlist, SoundCloud /sets/, Vimeo /album/, YouTube channel
# playlists tab). Cheap pre-filter only — the real answer comes from the
# yt-dlp probe below; this just spares a subprocess for the common case of a
# lone video URL.
_PLAYLIST_URL_RE = re.compile(
    r"[?&]list=|/playlist(?:[/?]|$)|/sets/|/album/|/playlists(?:[/?]|$)",
    re.IGNORECASE,
)


def _looks_like_playlist_url(url: str) -> bool:
    """Fast, no-subprocess pre-filter — NOT the authority on what is/isn't a
    playlist (the yt-dlp probe is); this only decides whether it's worth
    spending a probe at all."""
    return bool(_PLAYLIST_URL_RE.search(url or ""))


def _is_playlist_result(meta: dict) -> bool:
    """True if a `yt-dlp --flat-playlist --dump-single-json` result is an
    actual playlist/collection (has entries) rather than a lone video (a
    single video probed the same way carries no "entries" key at all)."""
    entries = meta.get("entries") if isinstance(meta, dict) else None
    return isinstance(entries, list) and len(entries) > 0


def _playlist_entries(meta: dict) -> List[dict]:
    """Ordered [{url, title, source_id}] extracted from a flat-playlist probe.
    source_id is stable across re-probes (used for the resume/skip logic) even
    when a title changes upstream."""
    out: List[dict] = []
    for e in (meta.get("entries") or []):
        if not isinstance(e, dict):
            continue
        vid = str(e.get("id") or "").strip()
        url = e.get("url") or e.get("webpage_url")
        if not url and vid:
            # --flat-playlist on a channel/tab extraction often yields a bare
            # id with no url/webpage_url — reconstruct a canonical watch URL
            # (only safe for extractors we know the URL shape of).
            ie = (e.get("ie_key") or "").lower()
            if not ie or "youtube" in ie:
                url = f"https://www.youtube.com/watch?v={vid}"
        if not url:
            continue
        title = (e.get("title") or vid or url).strip()
        out.append({"url": url, "title": title, "source_id": vid or url})
    return out


async def _probe_playlist(url: str) -> dict:
    """Metadata-only yt-dlp probe (no download). Raises RuntimeError with a
    user-safe message on failure/timeout/missing yt-dlp."""
    if not shutil.which(YTDLP_BIN):
        raise RuntimeError(
            "yt-dlp not found on host — install it (secubox-peertube Recommends: yt-dlp)")
    argv = [YTDLP_BIN, "--flat-playlist", "--dump-single-json", "--no-warnings", url]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), timeout=PLAYLIST_PROBE_TIMEOUT)
    except asyncio.TimeoutError:
        raise RuntimeError("playlist probe timed out")
    except FileNotFoundError:
        raise RuntimeError("yt-dlp not found on host")
    if proc.returncode != 0:
        tail = err.decode("utf-8", "replace").strip().splitlines()
        raise RuntimeError((tail[-1] if tail else "yt-dlp probe failed")[:200])
    try:
        return json.loads(out.decode("utf-8", "replace"))
    except ValueError:
        raise RuntimeError("unreadable playlist metadata")


async def _await_import_terminal(import_id, token: str,
                                  timeout: int = PLAYLIST_ITEM_TIMEOUT,
                                  poll_interval: int = PLAYLIST_POLL_INTERVAL) -> dict:
    """Poll PeerTube's own import list until OUR import_id reaches a terminal
    state (success/failed/rejected/cancelled) or `timeout` elapses.

    This IS the concurrency bound in practice: the worker blocks HERE
    (via asyncio.sleep, never busy-waiting) instead of firing the next
    import — so the event loop stays free for every other request while a
    playlist grinds through, and PeerTube never sees more than one
    playlist-triggered import in flight."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = await asyncio.to_thread(
            pt_api, "/users/me/videos/imports?count=50&sort=-createdAt", "GET", None, token, 20)
        if result.get("success") and isinstance(result.get("data"), dict):
            for row in (result["data"].get("data") or []):
                if row.get("id") == import_id:
                    label = ((row.get("state") or {}).get("label") or "").strip().lower()
                    if label in _TERMINAL_IMPORT_LABELS:
                        vid = (row.get("video") or {})
                        return {"terminal": True, "success": label == "success",
                                "label": label, "video_uuid": vid.get("uuid")}
                    break
        await asyncio.sleep(poll_interval)
    return {"terminal": False, "success": False, "label": "timeout", "video_uuid": None}


def _atomic_write_json(path: Path, data) -> None:
    """Write JSON atomically: temp file in the SAME directory as the target,
    then os.replace() — never through /tmp (CLAUDE.md)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp{os.getpid()}")
    tmp.write_text(json.dumps(data))
    os.replace(tmp, path)


def _save_playlist_jobs():
    try:
        _atomic_write_json(PLAYLIST_JOBS_FILE, list(_playlist_jobs.values()))
    except Exception as e:
        log.error(f"playlist jobs save failed: {e}")


def _load_playlist_jobs():
    if not PLAYLIST_JOBS_FILE.exists():
        return
    try:
        for j in json.loads(PLAYLIST_JOBS_FILE.read_text()):
            if j.get("status") in ("running", "queued"):
                # Stale from a previous daemon run/crash. Items already
                # marked "done" stay done (resume honors them via
                # _carry_forward_done); the job itself is surfaced as
                # interrupted rather than silently vanishing.
                j["status"] = "error"
                j["error"] = "interrupted (daemon restart)"
            _playlist_jobs[j["id"]] = j
    except Exception as e:
        log.error(f"playlist jobs load failed: {e}")


def _carry_forward_done(target_url: str, entries: List[dict]) -> List[dict]:
    """Resume support: any entry already marked 'done' in a PREVIOUS job for
    this exact playlist URL is carried forward as done — not re-submitted.
    Matched by source_id, which stays stable even if a title changes."""
    done_by_source: Dict[str, dict] = {}
    for job in _playlist_jobs.values():
        if job.get("target_url") != target_url:
            continue
        for it in job.get("items", []):
            if it.get("status") == "done" and it.get("source_id"):
                done_by_source[it["source_id"]] = it
    items = []
    for e in entries:
        prior = done_by_source.get(e["source_id"])
        if prior:
            items.append({**e, "status": "done", "video_uuid": prior.get("video_uuid"),
                          "import_id": prior.get("import_id"), "error": None})
        else:
            items.append({**e, "status": "pending", "video_uuid": None,
                          "import_id": None, "error": None})
    return items


def _item_name(job: dict, item: dict) -> Optional[str]:
    prefix = job.get("name_prefix")
    return f"{prefix} — {item['title']}" if prefix else None


def _ensure_playlist_worker():
    """Lazily start the single global playlist worker. secubox-peertube runs
    as its own standalone uvicorn process (own systemd unit + socket, not
    aggregator-mounted), so @app.on_event("startup") does fire here — but
    lazy-start is defensive, matches the pattern already used by
    secubox-mediaflow's clone worker, and lets tests avoid a real
    background task."""
    global _playlist_worker_task, _playlist_queue
    if _playlist_queue is None:
        _playlist_queue = asyncio.Queue()
    if not _playlist_jobs and PLAYLIST_JOBS_FILE.exists():
        _load_playlist_jobs()
    if _playlist_worker_task is None or _playlist_worker_task.done():
        _playlist_worker_task = asyncio.create_task(_playlist_worker())


async def _playlist_worker():
    """Single global consumer: playlist JOBS are processed one at a time too
    (not interleaved) — see the module docstring above for why."""
    while True:
        job_id = await _playlist_queue.get()
        try:
            await _process_playlist_job(job_id)
        except Exception as e:
            job = _playlist_jobs.get(job_id)
            if job:
                job["status"] = "error"
                job["error"] = str(e)
                _save_playlist_jobs()
            log.error(f"playlist job {job_id} crashed: {e}")
        finally:
            _playlist_queue.task_done()


async def _process_playlist_job(job_id: str):
    """Sequentially submit + await each pending item. One item's failure is
    recorded and the loop MOVES ON — it never aborts the rest of the
    playlist. Cancellation is checked before each item so a cancel takes
    effect promptly without needing to interrupt an item already submitted
    to PeerTube (which has no reliable cancel-in-flight of its own)."""
    job = _playlist_jobs.get(job_id)
    if not job:
        return
    token = get_admin_token()
    if not token:
        job["status"] = "error"
        job["error"] = "no admin credentials at /etc/secubox/secrets/peertube-admin"
        _save_playlist_jobs()
        return
    if job.get("status") != "cancelling":
        job["status"] = "running"
    _save_playlist_jobs()
    for idx, item in enumerate(job["items"]):
        if job.get("status") == "cancelling":
            break
        if item.get("status") == "done":
            continue
        job["current_index"] = idx
        item["status"] = "running"
        _save_playlist_jobs()
        sub = await _submit_import(item["url"], job.get("channel_id"),
                                    job.get("privacy", 1), _item_name(job, item), token)
        if not sub.get("success"):
            item["status"] = "error"
            item["error"] = sub.get("error", "import failed")
            _save_playlist_jobs()
            continue  # one failure never aborts the playlist
        res = await _await_import_terminal(sub.get("import_id"), token)
        if res.get("success"):
            item["status"] = "done"
            item["video_uuid"] = res.get("video_uuid")
            item["import_id"] = sub.get("import_id")
            item["error"] = None
        else:
            item["status"] = "error"
            item["import_id"] = sub.get("import_id")
            item["error"] = res.get("label", "failed")
        _save_playlist_jobs()
    job["current_index"] = -1
    job["status"] = "cancelled" if job.get("status") == "cancelling" else "complete"
    _save_playlist_jobs()


def _playlist_job_summary(job: dict) -> dict:
    items = job.get("items", [])
    done = sum(1 for i in items if i["status"] == "done")
    errors = sum(1 for i in items if i["status"] == "error")
    cur = job.get("current_index", -1)
    current_title = items[cur]["title"] if items and 0 <= cur < len(items) else None
    return {"id": job["id"], "target_url": job.get("target_url"), "title": job.get("title"),
            "status": job.get("status"), "total": len(items), "done": done, "errors": errors,
            "current_title": current_title, "created_at": job.get("created_at"),
            "error": job.get("error")}


@router.post("/playlist/import")
async def import_playlist(req: PlaylistImport, user=Depends(require_jwt)):
    """Queue every video of a playlist URL for sequential native import.

    A URL that doesn't even look playlist-shaped never spends a yt-dlp probe
    (see _looks_like_playlist_url) — use /import for a single video instead."""
    if not is_running():
        return {"success": False, "error": "PeerTube not reachable"}
    if not _looks_like_playlist_url(req.target_url):
        return {"success": False, "is_playlist": False,
                "error": "URL does not look like a playlist — use Import for a single video"}
    token = get_admin_token()
    if not token:
        return {"success": False,
                "error": "No admin credentials at /etc/secubox/secrets/peertube-admin"}
    try:
        meta = await _probe_playlist(req.target_url)
    except RuntimeError as e:
        return {"success": False, "error": str(e)}
    if not _is_playlist_result(meta):
        return {"success": False, "is_playlist": False,
                "error": "not a playlist (single video) — use Import instead"}
    entries = _playlist_entries(meta)
    if not entries:
        return {"success": False, "is_playlist": True,
                "error": "playlist has no downloadable entries"}
    channel_id = req.channel_id or default_channel_id(token)
    if not channel_id:
        return {"success": False, "error": "could not resolve a target channel"}
    if not _playlist_jobs and PLAYLIST_JOBS_FILE.exists():
        _load_playlist_jobs()
    items = _carry_forward_done(req.target_url, entries)
    job_id = secrets.token_hex(8)
    job = {
        "id": job_id, "target_url": req.target_url,
        "title": (meta.get("title") or req.target_url).strip(),
        "channel_id": channel_id, "privacy": req.privacy, "name_prefix": req.name_prefix,
        "created_at": int(time.time()), "status": "queued", "current_index": -1,
        "items": items, "error": None,
    }
    _playlist_jobs[job_id] = job
    _save_playlist_jobs()
    already_done = sum(1 for i in items if i["status"] == "done")
    _ensure_playlist_worker()
    await _playlist_queue.put(job_id)
    log.info(f"Queued playlist import ({len(items)} videos, {already_done} already done) "
             f"{req.target_url} by {user.get('sub', 'unknown')}")
    return {"success": True, "job_id": job_id, "total": len(items),
            "already_done": already_done, "title": job["title"]}


@router.get("/playlist/jobs")
async def playlist_jobs(user=Depends(require_jwt)):
    if not _playlist_jobs and PLAYLIST_JOBS_FILE.exists():
        _load_playlist_jobs()
    jobs = sorted(_playlist_jobs.values(), key=lambda j: j.get("created_at", 0), reverse=True)
    return {"jobs": [_playlist_job_summary(j) for j in jobs]}


@router.get("/playlist/jobs/{job_id}")
async def playlist_job_detail(job_id: str, user=Depends(require_jwt)):
    job = _playlist_jobs.get(job_id)
    if not job:
        if PLAYLIST_JOBS_FILE.exists():
            _load_playlist_jobs()
        job = _playlist_jobs.get(job_id)
    if not job:
        raise HTTPException(404, "playlist job not found")
    return job


@router.post("/playlist/jobs/{job_id}/cancel")
async def cancel_playlist_job(job_id: str, user=Depends(require_jwt)):
    job = _playlist_jobs.get(job_id)
    if not job:
        return {"success": False, "error": "not found"}
    if job.get("status") in ("complete", "cancelled", "error"):
        return {"success": True, "message": "already finished"}
    job["status"] = "cancelling"
    _save_playlist_jobs()
    log.info(f"Cancelling playlist job {job_id} by {user.get('sub', 'unknown')}")
    return {"success": True}


# Spool the dashboard (unprivileged secubox) writes; the root-run
# peertube-cookie-install.path/.service (#407) applies it — no sudo here (CSPN).
COOKIES_SPOOL = "/run/secubox/peertube-yt-cookies.txt"


@router.post("/import/cookies")
async def import_cookies(request: Request, user=Depends(require_jwt)):
    """Queue operator-supplied YouTube cookies (Netscape format) for the import
    pipeline. Body = the cookies.txt text (the SecuBox WebExtension / avatar
    broker reads them from the logged-in browser and POSTs here, #401/#402).

    The dashboard stays unprivileged: it writes the spool, and the root
    peertube-cookie-install.path watches it and installs them into the LXC +
    restarts PeerTube (#407). No sudo, NoNewPrivileges intact."""
    body = (await request.body()).decode("utf-8", "replace")
    if "\t" not in body or "youtube" not in body.lower():
        return {"success": False, "error": "body is not a Netscape youtube cookies file"}
    try:
        with open(COOKIES_SPOOL, "w") as f:
            f.write(body)
        os.chmod(COOKIES_SPOOL, 0o600)
    except Exception as e:
        return {"success": False, "error": f"spool write failed: {e}"}
    log.info(f"Queued YouTube cookies ({len(body)} bytes) by {user.get('sub', 'unknown')}")
    return {"success": True,
            "message": "cookies queued; installing into the LXC + restarting PeerTube shortly"}


# ============================================================================
# Channel Management
# ============================================================================

@router.get("/channels")
async def list_channels(user=Depends(require_jwt)):
    if not is_running():
        return {"channels": [], "error": "PeerTube not reachable"}
    result = pt_api("/video-channels?count=100")
    if result.get("success") and isinstance(result.get("data"), dict):
        d = result["data"]
        return {"channels": d.get("data", []), "total": d.get("total", 0)}
    return {"channels": [], "total": 0}


@router.post("/channel")
async def create_channel(channel: ChannelCreate, user=Depends(require_jwt)):
    if not is_running():
        return {"success": False, "error": "PeerTube not reachable"}
    token = get_admin_token()
    log.info(f"Creating channel {channel.name} by {user.get('sub', 'unknown')}")
    result = pt_api("/video-channels", method="POST", token=token, data={
        "name": channel.name,
        "displayName": channel.display_name,
        "description": channel.description,
    })
    return {"success": result.get("success", False)}


@router.delete("/channel/{channel_name}")
async def delete_channel(channel_name: str, user=Depends(require_jwt)):
    if not is_running():
        return {"success": False, "error": "PeerTube not reachable"}
    token = get_admin_token()
    log.info(f"Deleting channel {channel_name} by {user.get('sub', 'unknown')}")
    result = pt_api(f"/video-channels/{channel_name}", method="DELETE", token=token)
    return {"success": result.get("success", False)}


# ============================================================================
# User Management
# ============================================================================

@router.get("/users")
async def list_users(user=Depends(require_jwt)):
    if not is_running():
        return {"users": [], "error": "PeerTube not reachable"}
    token = get_admin_token()
    result = pt_api("/users?count=100", token=token)
    if result.get("success") and isinstance(result.get("data"), dict):
        d = result["data"]
        return {"users": d.get("data", []), "total": d.get("total", 0)}
    return {"users": [], "total": 0}


@router.post("/user")
async def create_user(new_user: UserCreate, user=Depends(require_jwt)):
    if not is_running():
        return {"success": False, "error": "PeerTube not reachable"}
    token = get_admin_token()
    log.info(f"Creating user {new_user.username} by {user.get('sub', 'unknown')}")
    result = pt_api("/users", method="POST", token=token, data={
        "username": new_user.username,
        "email": new_user.email,
        "password": new_user.password,
        "role": new_user.role,
        "videoQuota": new_user.video_quota,
    })
    return {"success": result.get("success", False), "username": new_user.username}


@router.delete("/user/{user_id}")
async def delete_user(user_id: int, user=Depends(require_jwt)):
    if not is_running():
        return {"success": False, "error": "PeerTube not reachable"}
    token = get_admin_token()
    log.info(f"Deleting user {user_id} by {user.get('sub', 'unknown')}")
    result = pt_api(f"/users/{user_id}", method="DELETE", token=token)
    return {"success": result.get("success", False)}


# ============================================================================
# Federation (ActivityPub)
# ============================================================================

@router.get("/federation/followers")
async def get_followers(user=Depends(require_jwt)):
    if not is_running():
        return {"followers": [], "error": "PeerTube not reachable"}
    result = pt_api("/server/followers?count=100")
    if result.get("success") and isinstance(result.get("data"), dict):
        d = result["data"]
        return {"followers": d.get("data", []), "total": d.get("total", 0)}
    return {"followers": [], "total": 0}


@router.get("/federation/following")
async def get_following(user=Depends(require_jwt)):
    if not is_running():
        return {"following": [], "error": "PeerTube not reachable"}
    result = pt_api("/server/following?count=100")
    if result.get("success") and isinstance(result.get("data"), dict):
        d = result["data"]
        return {"following": d.get("data", []), "total": d.get("total", 0)}
    return {"following": [], "total": 0}


@router.post("/federation/follow")
async def follow_instance(req: FollowRequest, user=Depends(require_jwt)):
    if not is_running():
        return {"success": False, "error": "PeerTube not reachable"}
    token = get_admin_token()
    log.info(f"Following instances {req.hosts} by {user.get('sub', 'unknown')}")
    result = pt_api("/server/following", method="POST", token=token, data={"hosts": req.hosts})
    return {"success": result.get("success", False)}


@router.delete("/federation/following/{follow_id}")
async def unfollow_instance(follow_id: int, user=Depends(require_jwt)):
    if not is_running():
        return {"success": False, "error": "PeerTube not reachable"}
    token = get_admin_token()
    log.info(f"Unfollowing {follow_id} by {user.get('sub', 'unknown')}")
    result = pt_api(f"/server/following/{follow_id}", method="DELETE", token=token)
    return {"success": result.get("success", False)}


# ============================================================================
# Transcoding
# ============================================================================

@router.get("/transcoding/jobs")
async def get_transcoding_jobs(user=Depends(require_jwt)):
    if not is_running():
        return {"jobs": [], "error": "PeerTube not reachable"}
    token = get_admin_token()
    result = pt_api("/jobs/video-transcoding?count=50", token=token)
    if result.get("success") and isinstance(result.get("data"), dict):
        d = result["data"]
        return {"jobs": d.get("data", []), "total": d.get("total", 0)}
    return {"jobs": [], "total": 0}


BACKLOG_CACHE = Path("/var/cache/secubox/peertube/backlog.json")

# PeerTube video.state, as stored in the DB.
_VIDEO_STATES = {1: "published", 2: "to_transcode", 3: "to_import",
                 4: "waiting_for_live", 5: "live_ended",
                 6: "to_move_to_external_storage", 7: "transcoding_failed",
                 8: "to_edit"}


@router.get("/transcoding/backlog")
async def get_transcoding_backlog(user=Depends(require_jwt)):
    """How many videos are still waiting, and how many are not yet PLAYABLE.

    `without_hls` is the number that matters: with web_videos disabled PeerTube
    only ever serves HLS, so a video with no playlist is unplayable — not merely
    un-optimised. Neither `/status` nor the PeerTube job list surfaces this, so
    a full queue used to look like a healthy instance.

    Served from the cache written by peertube-backlog.timer (root, lxc-attach +
    SQL, ~2 s). The request path is a file read: the dashboard stays
    unprivileged and NoNewPrivileges=true.
    """
    try:
        raw = json.loads(BACKLOG_CACHE.read_text())
    except FileNotFoundError:
        return {"available": False, "reason": "cache not written yet",
                "states": [], "pending": 0, "unplayable": 0}
    except (OSError, ValueError) as exc:
        log.warning("backlog cache unreadable: %s", exc)
        return {"available": False, "reason": "cache unreadable",
                "states": [], "pending": 0, "unplayable": 0}

    rows = raw.get("states") or []
    out = []
    for r in rows:
        out.append({
            "state": r.get("state"),
            "label": _VIDEO_STATES.get(r.get("state"), f"state_{r.get('state')}"),
            "videos": r.get("videos", 0),
            "without_hls": r.get("without_hls", 0),
        })
    pending = sum(r["videos"] for r in out if r["state"] == 2)
    unplayable = sum(r["without_hls"] for r in out if r["state"] != 1)
    age = None
    try:
        age = int(time.time() - BACKLOG_CACHE.stat().st_mtime)
    except OSError:
        pass
    # `stuck` is the #943 failure mode: counters claim jobs are pending while
    # nothing is queued or running. It froze the whole queue for 18 days
    # without a single surface reporting it — so it is reported here, where
    # the panel and the companion already look.
    return {"available": True, "states": out, "pending": pending,
            "unplayable": unplayable, "cache_age_seconds": age,
            "stuck": bool(raw.get("stuck")),
            "jobs_in_flight": raw.get("jobs_in_flight"),
            "pending_counters": raw.get("pending_counters")}


@router.get("/transcoding/settings")
async def get_transcoding_settings(user=Depends(require_jwt)):
    cfg = get_config()
    return {
        "enabled": cfg.get("transcoding_enabled", True),
        "threads": cfg.get("transcoding_threads", 2),
        "hls_enabled": cfg.get("hls_enabled", True),
        "webtorrent_enabled": cfg.get("webtorrent_enabled", True),
        "resolutions": cfg.get("transcoding_resolutions", {
            "240p": True, "360p": True, "480p": True, "720p": True,
            "1080p": True, "1440p": False, "2160p": False,
        })
    }


@router.post("/transcoding/settings")
async def update_transcoding_settings(settings: TranscodingSettings, user=Depends(require_jwt)):
    cfg = get_config()
    cfg["transcoding_enabled"] = settings.enabled
    cfg["transcoding_threads"] = settings.threads
    cfg["hls_enabled"] = settings.hls_enabled
    cfg["webtorrent_enabled"] = settings.webtorrent_enabled
    cfg["transcoding_resolutions"] = settings.resolutions
    save_config(cfg)
    log.info(f"Transcoding settings updated by {user.get('sub', 'unknown')}")
    return {"success": True, "message": "Restart PeerTube to apply changes"}


# ============================================================================
# Storage
# ============================================================================

@router.get("/storage/stats")
def get_storage_stats(user=Depends(require_jwt)):
    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/data/peertube"))
    stats = {"total": "", "videos": "", "thumbnails": "",
             "torrents": "", "streaming_playlists": ""}
    if not data_path.exists():
        return {"stats": stats, "error": "Data path not found"}
    try:
        r = subprocess.run(["du", "-sh", str(data_path)],
                           capture_output=True, text=True, timeout=30)
        if r.stdout:
            stats["total"] = r.stdout.split()[0]
        storage_path = data_path / "storage"
        for subdir in ["videos", "thumbnails", "torrents", "streaming-playlists"]:
            sp = storage_path / subdir
            if sp.exists():
                r = subprocess.run(["du", "-sh", str(sp)],
                                   capture_output=True, text=True, timeout=30)
                if r.stdout:
                    stats[subdir.replace("-", "_")] = r.stdout.split()[0]
    except Exception as e:
        return {"stats": stats, "error": str(e)}
    return {"stats": stats}


# ============================================================================
# Plugins
# ============================================================================

@router.get("/plugins")
async def list_plugins(user=Depends(require_jwt)):
    if not is_running():
        return {"plugins": [], "error": "PeerTube not reachable"}
    token = get_admin_token()
    result = pt_api("/plugins?count=100", token=token)
    if result.get("success") and isinstance(result.get("data"), dict):
        d = result["data"]
        return {"plugins": d.get("data", []), "total": d.get("total", 0)}
    return {"plugins": [], "total": 0}


@router.post("/plugin/install")
async def install_plugin(plugin: PluginInstall, user=Depends(require_jwt)):
    if not is_running():
        return {"success": False, "error": "PeerTube not reachable"}
    token = get_admin_token()
    log.info(f"Installing plugin {plugin.npm_name} by {user.get('sub', 'unknown')}")
    result = pt_api("/plugins/install", method="POST", token=token,
                    data={"npmName": plugin.npm_name})
    return {"success": result.get("success", False)}


@router.delete("/plugin/{plugin_name}")
async def uninstall_plugin(plugin_name: str, user=Depends(require_jwt)):
    if not is_running():
        return {"success": False, "error": "PeerTube not reachable"}
    token = get_admin_token()
    log.info(f"Uninstalling plugin {plugin_name} by {user.get('sub', 'unknown')}")
    result = pt_api("/plugins/uninstall", method="POST", token=token,
                    data={"npmName": plugin_name})
    return {"success": result.get("success", False)}


# ============================================================================
# LXC lifecycle (was "Container Management" — now native-LXC via peertubectl)
# ============================================================================

def _peertubectl(verb: str, timeout: int = 30) -> dict:
    try:
        r = subprocess.run([PEERTUBECTL, verb], capture_output=True, text=True, timeout=timeout)
        return {"success": r.returncode == 0, "stdout": r.stdout, "stderr": r.stderr}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _peertubectl_json(verb: str, timeout: int = 30) -> dict:
    """Verbe ctl dont la sortie est du JSON (#993).

    `_peertubectl` renvoie stdout brut ; pour version-status et check-upgrade
    le panneau attend l'objet lui-meme, pas une enveloppe."""
    r = _peertubectl(verb, timeout=timeout)
    if not r.get("success"):
        raise HTTPException(status_code=500,
                            detail=(r.get("stderr") or r.get("error") or "peertubectl failed")[:500])
    try:
        return json.loads(r.get("stdout") or "{}")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500,
                            detail=f"peertubectl {verb} emitted non-JSON: {(r.get('stdout') or '')[:200]!r}")


@router.get("/version-status")
async def version_status(user=Depends(require_jwt)):
    """Version installee + derniere version connue, depuis le CACHE.

    Ne sort jamais vers le reseau : c'est le minuteur quotidien qui interroge
    GitHub. Le faire dans le chemin de requete rendrait l'affichage du panneau
    dependant d'une limite de debit GitHub."""
    return _peertubectl_json("version-status", timeout=30)


@router.post("/check-upgrade")
async def check_upgrade(user=Depends(require_jwt)):
    """Releve immediat, a la demande. Sort vers le reseau et rafraichit le
    cache — d'ou un POST : ce n'est pas une lecture sans effet."""
    return _peertubectl_json("check-upgrade", timeout=60)


@router.post("/upgrade")
async def upgrade_peertube(user=Depends(require_jwt)):
    """Applique la mise a jour.

    DELIBEREMENT manuel et non declenche par le minuteur : un upgrade PeerTube
    migre la base et reconstruit — c'est long, et une lecture en cours est
    coupee. Le releve quotidien sert a SAVOIR, jamais a AGIR."""
    log.info(f"PeerTube upgrade requested by {user.get('sub', 'unknown')}")
    r = _peertubectl("upgrade", timeout=3600)
    if not r.get("success"):
        raise HTTPException(status_code=500,
                            detail=(r.get("stderr") or r.get("error") or "upgrade failed")[:500])
    return {"success": True, "output": (r.get("stdout") or "").strip().splitlines()[-5:]}


@router.get("/container/status")
async def container_status():
    """LXC + reachability status (kept under /container/* for webui back-compat)."""
    cfg = get_config()
    return {
        "runtime": "lxc-native",
        "lxc_state": get_lxc_state(),
        "http_reachable": http_reachable(),
        "lxc_ip": cfg.get("ip", "10.100.0.120"),
        "http_port": cfg.get("http_port", 9000),
    }


@router.post("/container/install")
def install_peertube(user=Depends(require_jwt)):
    """Provision the LXC + native PeerTube install. Long-running → detached."""
    if not Path(INSTALL_LIB).exists():
        return {"success": False, "error": f"install script missing at {INSTALL_LIB}"}
    log.info(f"Launching native-LXC PeerTube install by {user.get('sub', 'unknown')}")
    try:
        # Detach: install takes several minutes (apt + pnpm + release download).
        subprocess.Popen(
            ["bash", INSTALL_LIB],
            stdout=open("/var/log/secubox/peertube-install.log", "a"),
            stderr=subprocess.STDOUT, start_new_session=True,
        )
        return {"success": True,
                "message": "Install started (several minutes). "
                           "Follow /var/log/secubox/peertube-install.log or 'peertubectl logs'."}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/start")
async def start_peertube(user=Depends(require_jwt)):
    log.info(f"Starting PeerTube LXC by {user.get('sub', 'unknown')}")
    r = _peertubectl("start")
    return {"success": r.get("success", False), "output": r.get("stdout", r.get("error", ""))}


@router.post("/container/stop")
async def stop_peertube(user=Depends(require_jwt)):
    log.info(f"Stopping PeerTube LXC by {user.get('sub', 'unknown')}")
    r = _peertubectl("stop")
    return {"success": r.get("success", False), "output": r.get("stdout", r.get("error", ""))}


@router.post("/container/restart")
async def restart_peertube(user=Depends(require_jwt)):
    log.info(f"Restarting PeerTube LXC by {user.get('sub', 'unknown')}")
    r = _peertubectl("restart")
    return {"success": r.get("success", False), "output": r.get("stdout", r.get("error", ""))}


@router.post("/container/uninstall")
async def uninstall_peertube(user=Depends(require_jwt)):
    """Stop the LXC (data on /data/peertube is preserved)."""
    log.info(f"Stopping PeerTube LXC (data preserved) by {user.get('sub', 'unknown')}")
    r = _peertubectl("stop")
    return {"success": r.get("success", False),
            "message": "LXC stopped, data preserved at /data/peertube"}


# ============================================================================
# Logs
# ============================================================================

@router.get("/logs")
def get_logs(lines: int = 100, user=Depends(require_jwt)):
    """Tail peertube.service journal inside the LXC."""
    cfg = get_config()
    try:
        r = subprocess.run(
            ["lxc-attach", "-n", cfg["name"], "-P", cfg["path"], "--",
             "journalctl", "-u", "peertube", "-n", str(lines), "--no-pager"],
            capture_output=True, text=True, timeout=15,
        )
        return {"logs": (r.stdout + r.stderr) or "No logs available"}
    except Exception:
        return {"logs": "No logs available"}


# ============================================================================
# Configuration
# ============================================================================

@router.get("/config")
async def get_peertube_config(user=Depends(require_jwt)):
    return get_config()


@router.post("/config")
async def set_peertube_config(config: PeerTubeConfig, user=Depends(require_jwt)):
    cfg = get_config()
    cfg.update(config.model_dump())
    save_config(cfg)
    log.info(f"Config updated by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Admin Operations (Spool-Based)
# ============================================================================

@router.get("/admin/op/{op_id}")
async def get_op_result(op_id: str, user=Depends(require_jwt)):
    """Poll the result of a spooled admin op (reset-password / upgrade)."""
    return _read_op_result(op_id)


@router.post("/admin/reset-password")
async def reset_password_op(body: ResetPasswordBody, user=Depends(require_admin)):
    """Reset the PeerTube admin (root) password. Lockout-safe: runs the PeerTube
    CLI in the LXC via the root spool, then rewrites the admin secret. If no
    password is given, a strong one is generated and returned in the op result."""
    pw = body.password or secrets.token_urlsafe(18)
    op_id = _spool_op("reset-admin-password", password=pw)
    return {"success": True, "id": op_id}


# ============================================================================
# Version Check (issue #798)
# ============================================================================

def _semver_lt(a: str, b: str) -> bool:
    """True if version a < b (numeric field compare; tolerates a leading 'v')."""
    def parts(v):
        v = (v or "").lstrip("vV").split("-")[0]
        return [int(x) for x in re.findall(r"\d+", v)] or [0]
    pa, pb = parts(a), parts(b)
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa)); pb += [0] * (n - len(pb))
    return pa < pb


def _installed_version() -> Optional[str]:
    r = pt_api("/config")
    if r.get("success") and isinstance(r.get("data"), dict):
        return r["data"].get("serverVersion")
    return None


def _latest_version() -> Optional[str]:
    """Latest PeerTube release tag from GitHub, cached ~1h in /run. Best-effort:
    returns None offline / on rate-limit (never blocks the dashboard)."""
    cache = OPS_DIR.parent / "latest-version.json"
    try:
        if cache.exists() and (time.time() - cache.stat().st_mtime) < 3600:
            return json.loads(cache.read_text()).get("latest")
    except Exception:
        pass
    try:
        out = subprocess.run(
            ["curl", "-s", "--max-time", "8",
             "https://api.github.com/repos/Chocobozzz/PeerTube/releases/latest"],
            capture_output=True, text=True, timeout=12)
        tag = json.loads(out.stdout).get("tag_name")
        if tag:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps({"latest": tag}))
        return tag
    except Exception:
        return None


@router.get("/version")
async def version_info(user=Depends(require_jwt)):
    installed = _installed_version()
    latest = _latest_version()
    up = bool(installed and latest and _semver_lt(installed, latest))
    return {"installed": installed, "latest": latest, "upgrade_available": up}


# ============================================================================
# Upgrade (issue #798)
# ============================================================================

class UpgradeBody(BaseModel):
    target: Optional[str] = "latest"


@router.post("/upgrade")
async def upgrade_op(body: UpgradeBody, user=Depends(require_admin)):
    """Upgrade PeerTube in the LXC (backup → download → migrate → restart) via the
    root spool. Poll GET /admin/op/{id}; the op reports running/done/error."""
    op_id = _spool_op("upgrade", target=body.target or "latest")
    return {"success": True, "id": op_id}


app.include_router(router)
