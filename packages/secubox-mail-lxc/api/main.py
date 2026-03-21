"""SecuBox Mail LXC - Container Management for Postfix/Dovecot Mail Server"""
import subprocess
import shutil
from pathlib import Path
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Mail LXC")

LXC_NAME = "mail"
LXC_PATH = "/srv/lxc"
LXC_ROOTFS = f"{LXC_PATH}/{LXC_NAME}/rootfs"
LXC_CONFIG = f"{LXC_PATH}/{LXC_NAME}/config"
DATA_PATH = "/srv/mail"
ALPINE_VERSION = "3.21"


def _cfg():
    cfg = get_config("mail-lxc")
    return {
        "lxc_path": cfg.get("lxc_path", LXC_PATH) if cfg else LXC_PATH,
        "data_path": cfg.get("data_path", DATA_PATH) if cfg else DATA_PATH,
        "memory_limit": cfg.get("memory_limit", "512M") if cfg else "512M",
        "hostname": cfg.get("hostname", "mail.secubox.local") if cfg else "mail.secubox.local",
        "domain": cfg.get("domain", "secubox.local") if cfg else "secubox.local",
    }


def _lxc_exists() -> bool:
    return Path(LXC_CONFIG).exists() and Path(LXC_ROOTFS).exists()


def _lxc_running() -> bool:
    result = subprocess.run(["lxc-info", "-n", LXC_NAME, "-s"], capture_output=True, text=True)
    return "RUNNING" in result.stdout


def _get_ip() -> Optional[str]:
    if not _lxc_running():
        return None
    result = subprocess.run(["lxc-info", "-n", LXC_NAME, "-iH"], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def _lxc_exec(cmd: List[str], timeout: int = 30) -> dict:
    if not _lxc_running():
        return {"success": False, "error": "Container not running"}
    try:
        result = subprocess.run(["lxc-attach", "-n", LXC_NAME, "--"] + cmd,
                                capture_output=True, text=True, timeout=timeout)
        return {"success": result.returncode == 0, "stdout": result.stdout, "stderr": result.stderr}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timeout"}


def _get_arch() -> str:
    import platform
    return {"x86_64": "x86_64", "aarch64": "aarch64", "armv7l": "armv7"}.get(platform.machine(), "x86_64")


def _parse_mem(mem_str: str) -> int:
    mem_str = mem_str.upper()
    if mem_str.endswith("G"): return int(mem_str[:-1]) * 1024**3
    if mem_str.endswith("M"): return int(mem_str[:-1]) * 1024**2
    if mem_str.endswith("K"): return int(mem_str[:-1]) * 1024
    return int(mem_str)


@app.get("/status")
async def status():
    cfg = _cfg()
    exists = _lxc_exists()
    running = _lxc_running() if exists else False
    return {
        "module": "mail-lxc", "container": LXC_NAME,
        "exists": exists, "running": running,
        "ip": _get_ip() if running else None,
        "hostname": cfg["hostname"], "domain": cfg["domain"],
        "ports": {"smtp": 25, "smtps": 465, "submission": 587, "imap": 143, "imaps": 993}
    }


@app.get("/info", dependencies=[Depends(require_jwt)])
async def info():
    cfg = _cfg()
    stats = {}
    if _lxc_running():
        result = subprocess.run(["lxc-info", "-n", LXC_NAME], capture_output=True, text=True)
        for line in result.stdout.strip().split("\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                stats[k.strip().lower().replace(" ", "_")] = v.strip()
    return {"config": cfg, "stats": stats, "paths": {"rootfs": LXC_ROOTFS, "data": DATA_PATH}}


class InstallReq(BaseModel):
    force: bool = False


@app.post("/install", dependencies=[Depends(require_jwt)])
async def install(req: InstallReq):
    if _lxc_exists() and not req.force:
        raise HTTPException(400, "Container exists. Use force=true.")
    if _lxc_running():
        subprocess.run(["lxc-stop", "-n", LXC_NAME, "-k"], timeout=30)

    cfg = _cfg()
    for d in ["mail", "config", "ssl", "logs"]:
        Path(f"{DATA_PATH}/{d}").mkdir(parents=True, exist_ok=True)

    arch = _get_arch()
    url = f"https://dl-cdn.alpinelinux.org/alpine/v{ALPINE_VERSION}/releases/{arch}/alpine-minirootfs-{ALPINE_VERSION}.0-{arch}.tar.gz"
    subprocess.run(["wget", "-q", "-O", "/tmp/alpine-mail.tar.gz", url], timeout=120, check=True)

    if Path(LXC_ROOTFS).exists(): shutil.rmtree(LXC_ROOTFS)
    Path(LXC_ROOTFS).mkdir(parents=True)
    subprocess.run(["tar", "-xzf", "/tmp/alpine-mail.tar.gz", "-C", LXC_ROOTFS], check=True)
    Path("/tmp/alpine-mail.tar.gz").unlink(missing_ok=True)
    shutil.copy("/etc/resolv.conf", f"{LXC_ROOTFS}/etc/resolv.conf")

    lxc_cfg = f"""lxc.uts.name = {LXC_NAME}
lxc.rootfs.path = dir:{LXC_ROOTFS}
lxc.arch = {arch}
lxc.net.0.type = none
lxc.mount.auto = proc:mixed sys:ro cgroup:mixed
lxc.mount.entry = {DATA_PATH}/mail srv/mail none bind,create=dir 0 0
lxc.mount.entry = {DATA_PATH}/config etc/mail-config none bind,create=dir 0 0
lxc.mount.entry = {DATA_PATH}/ssl etc/ssl/mail none bind,create=dir 0 0
lxc.mount.entry = {DATA_PATH}/logs var/log/mail none bind,create=dir 0 0
lxc.environment = MAIL_DOMAIN={cfg['domain']}
lxc.environment = MAIL_HOSTNAME={cfg['hostname']}
lxc.tty.max = 1
lxc.pty.max = 256
lxc.cgroup2.devices.allow = c 1:* rwm
lxc.cgroup2.devices.allow = c 5:* rwm
lxc.cgroup2.devices.allow = c 136:* rwm
lxc.cap.drop = sys_admin sys_module mac_admin mac_override sys_time sys_rawio
lxc.cgroup2.memory.max = {_parse_mem(cfg['memory_limit'])}
lxc.init.cmd = /etc/init.d/mail-init start
"""
    Path(LXC_CONFIG).parent.mkdir(parents=True, exist_ok=True)
    Path(LXC_CONFIG).write_text(lxc_cfg)

    init_script = """#!/bin/sh
setup() {
    apk update && apk add --no-cache postfix dovecot dovecot-lmtpd opendkim ca-certificates openssl
    postconf -e "myhostname=$MAIL_HOSTNAME" "mydomain=$MAIL_DOMAIN" "home_mailbox=Maildir/"
    cat > /etc/dovecot/local.conf << 'EOF'
protocols = imap lmtp
mail_location = maildir:~/Maildir
ssl = yes
ssl_cert = </etc/ssl/mail/fullchain.pem
ssl_key = </etc/ssl/mail/privkey.pem
EOF
    touch /etc/mail-setup-done
}
start_services() {
    [ -f /etc/ssl/mail/fullchain.pem ] || openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/mail/privkey.pem -out /etc/ssl/mail/fullchain.pem -subj "/CN=$MAIL_HOSTNAME"
    postfix start; dovecot; tail -f /var/log/mail/mail.log 2>/dev/null || sleep infinity
}
[ -f /etc/mail-setup-done ] || setup; start_services
"""
    init_path = Path(f"{LXC_ROOTFS}/etc/init.d")
    init_path.mkdir(parents=True, exist_ok=True)
    (init_path / "mail-init").write_text(init_script)
    (init_path / "mail-init").chmod(0o755)

    return {"success": True, "message": "Mail container installed", "rootfs": LXC_ROOTFS}


@app.post("/start", dependencies=[Depends(require_jwt)])
async def start():
    if not _lxc_exists(): raise HTTPException(400, "Not installed")
    if _lxc_running(): return {"success": True, "message": "Already running"}
    result = subprocess.run(["lxc-start", "-n", LXC_NAME, "-d"], capture_output=True, text=True, timeout=30)
    return {"success": result.returncode == 0}


@app.post("/stop", dependencies=[Depends(require_jwt)])
async def stop():
    if not _lxc_running(): return {"success": True, "message": "Already stopped"}
    result = subprocess.run(["lxc-stop", "-n", LXC_NAME], capture_output=True, text=True, timeout=30)
    return {"success": result.returncode == 0}


@app.post("/restart", dependencies=[Depends(require_jwt)])
async def restart():
    if _lxc_running(): subprocess.run(["lxc-stop", "-n", LXC_NAME], timeout=30)
    result = subprocess.run(["lxc-start", "-n", LXC_NAME, "-d"], capture_output=True, text=True, timeout=30)
    return {"success": result.returncode == 0}


@app.delete("/uninstall", dependencies=[Depends(require_jwt)])
async def uninstall():
    if _lxc_running(): subprocess.run(["lxc-stop", "-n", LXC_NAME, "-k"], timeout=30)
    lxc_dir = Path(f"{LXC_PATH}/{LXC_NAME}")
    if lxc_dir.exists(): shutil.rmtree(lxc_dir)
    return {"success": True}


@app.get("/logs", dependencies=[Depends(require_jwt)])
async def logs(lines: int = 100):
    log_file = Path(f"{DATA_PATH}/logs/mail.log")
    if not log_file.exists(): return {"logs": []}
    result = subprocess.run(["tail", "-n", str(lines), str(log_file)], capture_output=True, text=True)
    return {"logs": result.stdout.strip().split("\n") if result.stdout else []}


@app.get("/users", dependencies=[Depends(require_jwt)])
async def list_users():
    result = _lxc_exec(["cat", "/etc/mail-config/passwd"])
    users = []
    if result["success"]:
        for line in result["stdout"].strip().split("\n"):
            if line and ":" in line: users.append({"username": line.split(":")[0]})
    return {"users": users}


class MailUser(BaseModel):
    username: str
    password: str


@app.post("/user", dependencies=[Depends(require_jwt)])
async def add_user(user: MailUser):
    hash_r = subprocess.run(["openssl", "passwd", "-6", user.password], capture_output=True, text=True)
    entry = f"{user.username}:{hash_r.stdout.strip()}:1000:1000::/home/{user.username}:/sbin/nologin"
    _lxc_exec(["sh", "-c", f'echo "{entry}" >> /etc/mail-config/passwd'])
    _lxc_exec(["mkdir", "-p", f"/srv/mail/{user.username}/Maildir"])
    return {"success": True, "username": user.username}


@app.delete("/user/{username}", dependencies=[Depends(require_jwt)])
async def delete_user(username: str):
    result = _lxc_exec(["sed", "-i", f"/^{username}:/d", "/etc/mail-config/passwd"])
    return {"success": result["success"]}
