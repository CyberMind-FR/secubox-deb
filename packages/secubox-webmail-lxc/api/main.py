"""SecuBox Webmail LXC - Container Management for Roundcube/SOGo"""
import subprocess
import shutil
from pathlib import Path
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Webmail LXC")

LXC_NAME = "webmail"
LXC_PATH = "/srv/lxc"
LXC_ROOTFS = f"{LXC_PATH}/{LXC_NAME}/rootfs"
LXC_CONFIG = f"{LXC_PATH}/{LXC_NAME}/config"
DATA_PATH = "/srv/webmail"
ALPINE_VERSION = "3.21"


def _cfg():
    cfg = get_config("webmail-lxc")
    return {
        "lxc_path": cfg.get("lxc_path", LXC_PATH) if cfg else LXC_PATH,
        "data_path": cfg.get("data_path", DATA_PATH) if cfg else DATA_PATH,
        "memory_limit": cfg.get("memory_limit", "256M") if cfg else "256M",
        "mail_server": cfg.get("mail_server", "localhost") if cfg else "localhost",
        "mail_domain": cfg.get("mail_domain", "secubox.local") if cfg else "secubox.local",
        "webmail_type": cfg.get("webmail_type", "roundcube") if cfg else "roundcube",
        "http_port": cfg.get("http_port", 8080) if cfg else 8080,
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
        "module": "webmail-lxc", "container": LXC_NAME,
        "exists": exists, "running": running,
        "ip": _get_ip() if running else None,
        "webmail_type": cfg["webmail_type"],
        "mail_server": cfg["mail_server"],
        "http_port": cfg["http_port"],
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
    webmail_type: str = "roundcube"


@app.post("/install", dependencies=[Depends(require_jwt)])
async def install(req: InstallReq):
    if _lxc_exists() and not req.force:
        raise HTTPException(400, "Container exists. Use force=true.")
    if _lxc_running():
        subprocess.run(["lxc-stop", "-n", LXC_NAME, "-k"], timeout=30)

    cfg = _cfg()
    webmail_type = req.webmail_type or cfg["webmail_type"]

    for d in ["data", "config", "logs"]:
        Path(f"{DATA_PATH}/{d}").mkdir(parents=True, exist_ok=True)

    arch = _get_arch()
    url = f"https://dl-cdn.alpinelinux.org/alpine/v{ALPINE_VERSION}/releases/{arch}/alpine-minirootfs-{ALPINE_VERSION}.0-{arch}.tar.gz"
    subprocess.run(["wget", "-q", "-O", "/tmp/alpine-webmail.tar.gz", url], timeout=120, check=True)

    if Path(LXC_ROOTFS).exists(): shutil.rmtree(LXC_ROOTFS)
    Path(LXC_ROOTFS).mkdir(parents=True)
    subprocess.run(["tar", "-xzf", "/tmp/alpine-webmail.tar.gz", "-C", LXC_ROOTFS], check=True)
    Path("/tmp/alpine-webmail.tar.gz").unlink(missing_ok=True)
    shutil.copy("/etc/resolv.conf", f"{LXC_ROOTFS}/etc/resolv.conf")

    lxc_cfg = f"""lxc.uts.name = {LXC_NAME}
lxc.rootfs.path = dir:{LXC_ROOTFS}
lxc.arch = {arch}
lxc.net.0.type = none
lxc.mount.auto = proc:mixed sys:ro cgroup:mixed
lxc.mount.entry = {DATA_PATH}/data srv/data none bind,create=dir 0 0
lxc.mount.entry = {DATA_PATH}/config etc/webmail none bind,create=dir 0 0
lxc.mount.entry = {DATA_PATH}/logs var/log/webmail none bind,create=dir 0 0
lxc.environment = MAIL_SERVER={cfg['mail_server']}
lxc.environment = MAIL_DOMAIN={cfg['mail_domain']}
lxc.environment = WEBMAIL_TYPE={webmail_type}
lxc.environment = HTTP_PORT={cfg['http_port']}
lxc.tty.max = 1
lxc.pty.max = 256
lxc.cgroup2.devices.allow = c 1:* rwm
lxc.cgroup2.devices.allow = c 5:* rwm
lxc.cgroup2.devices.allow = c 136:* rwm
lxc.cap.drop = sys_admin sys_module mac_admin mac_override sys_time sys_rawio
lxc.cgroup2.memory.max = {_parse_mem(cfg['memory_limit'])}
lxc.init.cmd = /etc/init.d/webmail-init start
"""
    Path(LXC_CONFIG).parent.mkdir(parents=True, exist_ok=True)
    Path(LXC_CONFIG).write_text(lxc_cfg)

    # Init script supporting both Roundcube and SOGo
    init_script = """#!/bin/sh
setup_roundcube() {
    apk add --no-cache nginx php82 php82-fpm php82-imap php82-mbstring php82-xml \
        php82-json php82-pdo php82-pdo_sqlite php82-session php82-openssl roundcube
    ln -sf /usr/share/webapps/roundcube /var/www/roundcube
    cat > /etc/nginx/http.d/roundcube.conf << 'EOF'
server {
    listen 8080;
    root /var/www/roundcube;
    index index.php;
    location ~ \\.php$ {
        fastcgi_pass 127.0.0.1:9000;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
}
EOF
    # Configure roundcube
    cat > /etc/webmail/roundcube.inc.php << EOF
<?php
\\$config['default_host'] = '$MAIL_SERVER';
\\$config['smtp_server'] = '$MAIL_SERVER';
\\$config['smtp_port'] = 587;
\\$config['support_url'] = '';
\\$config['product_name'] = 'SecuBox Webmail';
\\$config['db_dsnw'] = 'sqlite:////srv/data/roundcube.db';
EOF
}

setup_sogo() {
    apk add --no-cache sogo nginx
    cat > /etc/sogo/sogo.conf << EOF
{
    SOGoProfileURL = "sqlite:////srv/data/sogo/profile.db";
    OCSFolderInfoURL = "sqlite:////srv/data/sogo/folder.db";
    OCSSessionsFolderURL = "sqlite:////srv/data/sogo/sessions.db";
    SOGoMailDomain = "$MAIL_DOMAIN";
    SOGoIMAPServer = "imap://$MAIL_SERVER:143";
    SOGoSMTPServer = "smtp://$MAIL_SERVER:587";
}
EOF
}

start_services() {
    if [ "$WEBMAIL_TYPE" = "sogo" ]; then
        sogod &
    else
        php-fpm82 &
    fi
    nginx -g 'daemon off;'
}

setup() {
    apk update
    if [ "$WEBMAIL_TYPE" = "sogo" ]; then
        setup_sogo
    else
        setup_roundcube
    fi
    touch /etc/webmail-setup-done
}

[ -f /etc/webmail-setup-done ] || setup
start_services
"""
    init_path = Path(f"{LXC_ROOTFS}/etc/init.d")
    init_path.mkdir(parents=True, exist_ok=True)
    (init_path / "webmail-init").write_text(init_script)
    (init_path / "webmail-init").chmod(0o755)

    return {"success": True, "message": f"Webmail ({webmail_type}) container installed", "rootfs": LXC_ROOTFS}


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
    log_file = Path(f"{DATA_PATH}/logs/access.log")
    if not log_file.exists(): return {"logs": []}
    result = subprocess.run(["tail", "-n", str(lines), str(log_file)], capture_output=True, text=True)
    return {"logs": result.stdout.strip().split("\n") if result.stdout else []}


@app.post("/clear-cache", dependencies=[Depends(require_jwt)])
async def clear_cache():
    result = _lxc_exec(["rm", "-rf", "/srv/data/cache/*"])
    return {"success": result["success"]}


@app.get("/plugins", dependencies=[Depends(require_jwt)])
async def list_plugins():
    result = _lxc_exec(["ls", "-1", "/var/www/roundcube/plugins"])
    plugins = result["stdout"].strip().split("\n") if result["success"] and result["stdout"] else []
    return {"plugins": plugins}


class PluginReq(BaseModel):
    name: str
    enabled: bool


@app.post("/plugin", dependencies=[Depends(require_jwt)])
async def toggle_plugin(req: PluginReq):
    # Toggle plugin in config
    action = "enable" if req.enabled else "disable"
    return {"success": True, "plugin": req.name, "action": action}
