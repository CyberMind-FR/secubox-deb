# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox VM API - Virtualization management."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import json
import os
import xml.etree.ElementTree as ET
from typing import Optional

app = FastAPI(title="SecuBox VM API", version="1.0.0")

VM_DIR = "/var/lib/secubox/vm"
ISO_DIR = "/var/lib/secubox/vm/iso"
DISK_DIR = "/var/lib/secubox/vm/disks"


class VMCreate(BaseModel):
    name: str
    memory: int = 2048  # MB
    vcpus: int = 2
    disk_size: int = 20  # GB
    iso: Optional[str] = None
    os_type: str = "linux"


class LXCCreate(BaseModel):
    name: str
    template: str = "debian"
    release: str = "bookworm"
    arch: str = "amd64"


def run_cmd(cmd: list, timeout: int = 60) -> tuple:
    """Run command and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1


def run_priv(cmd: list, timeout: int = 60) -> tuple:
    """Run a host privileged command via the read/lifecycle sudo grant.

    The aggregator mounts this module in-process as the unprivileged `secubox`
    user, which cannot see root's /var/lib/lxc containers — bare `lxc-ls`
    returns nothing, so the dashboard reported 0 containers (#601). The grant
    in /etc/sudoers.d/secubox-vm covers read + lifecycle only.
    """
    return run_cmd(["sudo", "-n"] + cmd, timeout=timeout)


def is_libvirt_running() -> bool:
    """Check if libvirtd is running."""
    _, _, code = run_cmd(["systemctl", "is-active", "--quiet", "libvirtd"])
    return code == 0


def is_lxc_available() -> bool:
    """Check if LXC is available."""
    _, _, code = run_cmd(["which", "lxc-ls"])
    return code == 0


def get_virsh_vms() -> list:
    """List all libvirt VMs."""
    vms = []
    stdout, _, code = run_cmd(["virsh", "list", "--all"])

    if code != 0:
        return vms

    for line in stdout.strip().split('\n')[2:]:  # Skip header
        parts = line.split()
        if len(parts) >= 2:
            vm_id = parts[0] if parts[0] != '-' else None
            name = parts[1]
            state = ' '.join(parts[2:]) if len(parts) > 2 else 'unknown'

            vms.append({
                "id": vm_id,
                "name": name,
                "state": state,
                "type": "kvm"
            })

    return vms


def get_lxc_containers() -> list:
    """List all LXC containers.

    On lit aussi AUTOSTART (#1225) : sans lui, l'interface ne pouvait ni
    montrer si un conteneur revient au boot, ni offrir un arret qui « tient ».
    L'etat FROZEN (mise en veille par lxc-freeze) est distingue de RUNNING pour
    que le bouton propose reveiller plutot que demarrer.
    """
    containers = []
    # NB: the memory column key is `RAM` — `MEMORY` is rejected by lxc-ls
    # ("Invalid key") and yields zero output (#601). AUTOSTART s'ajoute a la
    # meme requete, aucune commande de plus.
    stdout, _, code = run_priv(
        ["lxc-ls", "-f", "-F", "NAME,STATE,IPV4,RAM,AUTOSTART"])

    if code != 0:
        return containers

    for line in stdout.strip().split('\n')[1:]:  # Skip header
        parts = line.split()
        if len(parts) >= 2:
            state = parts[1].lower()
            containers.append({
                "name": parts[0],
                "state": state,
                "frozen": state == "frozen",
                "ip": parts[2] if len(parts) > 2 and parts[2] != '-' else None,
                "memory": parts[3] if len(parts) > 3 else None,
                # AUTOSTART rend "1"/"0" ; absent sur les tres vieux lxc-ls.
                "autostart": (len(parts) > 4 and parts[4] == "1"),
                "type": "lxc"
            })

    return containers


def get_vm_info(name: str) -> dict:
    """Get detailed VM info via virsh."""
    info = {"name": name}

    # Basic info
    stdout, _, code = run_cmd(["virsh", "dominfo", name])
    if code == 0:
        for line in stdout.strip().split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                info[key.strip().lower().replace(' ', '_')] = value.strip()

    # Memory and CPU
    stdout, _, _ = run_cmd(["virsh", "domstats", name, "--raw"])

    return info


def get_lxc_info(name: str) -> dict:
    """Get detailed LXC container info."""
    info = {"name": name, "type": "lxc"}

    stdout, _, code = run_priv(["lxc-info", "-n", name])
    if code == 0:
        for line in stdout.strip().split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                info[key.strip().lower().replace(' ', '_')] = value.strip()

    return info


@app.get("/health")
def health():
    return {"status": "ok", "service": "vm"}


@app.get("/status")
def get_status():
    """Get virtualization status."""
    libvirt_ok = is_libvirt_running()
    lxc_ok = is_lxc_available()

    vms = get_virsh_vms() if libvirt_ok else []
    containers = get_lxc_containers() if lxc_ok else []

    running_vms = len([v for v in vms if 'running' in v.get('state', '').lower()])
    running_containers = len([c for c in containers if c.get('state') == 'running'])

    # Check KVM support
    kvm_ok = os.path.exists("/dev/kvm")

    return {
        "libvirt": {
            "available": libvirt_ok,
            "kvm_enabled": kvm_ok
        },
        "lxc": {
            "available": lxc_ok
        },
        "vms": {
            "total": len(vms),
            "running": running_vms
        },
        "containers": {
            "total": len(containers),
            "running": running_containers
        }
    }


@app.get("/vms")
def list_vms():
    """List all VMs (KVM + LXC)."""
    vms = []

    if is_libvirt_running():
        vms.extend(get_virsh_vms())

    if is_lxc_available():
        vms.extend(get_lxc_containers())

    return {"vms": vms}


@app.get("/vms/kvm")
def list_kvm_vms():
    """List KVM virtual machines."""
    if not is_libvirt_running():
        raise HTTPException(status_code=503, detail="libvirtd not running")
    return {"vms": get_virsh_vms()}


@app.get("/vms/lxc")
def list_lxc_containers():
    """List LXC containers."""
    if not is_lxc_available():
        raise HTTPException(status_code=503, detail="LXC not available")
    return {"containers": get_lxc_containers()}


@app.get("/vms/{name}")
def get_vm(name: str):
    """Get VM or container details."""
    # Try KVM first
    if is_libvirt_running():
        for vm in get_virsh_vms():
            if vm["name"] == name:
                return get_vm_info(name)

    # Try LXC
    if is_lxc_available():
        for c in get_lxc_containers():
            if c["name"] == name:
                return get_lxc_info(name)

    raise HTTPException(status_code=404, detail="VM not found")


@app.post("/vms/kvm")
def create_kvm_vm(config: VMCreate):
    """Create a new KVM virtual machine."""
    if not is_libvirt_running():
        raise HTTPException(status_code=503, detail="libvirtd not running")

    os.makedirs(DISK_DIR, exist_ok=True)

    # Check if VM already exists
    for vm in get_virsh_vms():
        if vm["name"] == config.name:
            raise HTTPException(status_code=409, detail="VM already exists")

    disk_path = f"{DISK_DIR}/{config.name}.qcow2"

    # Create disk image
    stdout, stderr, code = run_cmd([
        "qemu-img", "create", "-f", "qcow2", disk_path, f"{config.disk_size}G"
    ])

    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to create disk: {stderr}")

    # Build virt-install command
    cmd = [
        "virt-install",
        "--name", config.name,
        "--memory", str(config.memory),
        "--vcpus", str(config.vcpus),
        "--disk", f"path={disk_path},format=qcow2",
        "--os-variant", "generic",
        "--graphics", "vnc,listen=0.0.0.0",
        "--noautoconsole"
    ]

    if config.iso:
        iso_path = os.path.join(ISO_DIR, config.iso)
        if os.path.exists(iso_path):
            cmd.extend(["--cdrom", iso_path])
        else:
            cmd.extend(["--cdrom", config.iso])
    else:
        cmd.append("--import")

    stdout, stderr, code = run_cmd(cmd, timeout=120)

    if code != 0:
        # Cleanup disk on failure
        if os.path.exists(disk_path):
            os.remove(disk_path)
        raise HTTPException(status_code=500, detail=f"Failed to create VM: {stderr}")

    return {"status": "created", "name": config.name}


@app.post("/vms/lxc")
def create_lxc_container(config: LXCCreate):
    """Create a new LXC container."""
    if not is_lxc_available():
        raise HTTPException(status_code=503, detail="LXC not available")

    # Check if container exists
    for c in get_lxc_containers():
        if c["name"] == config.name:
            raise HTTPException(status_code=409, detail="Container already exists")

    cmd = [
        "lxc-create",
        "-n", config.name,
        "-t", "download",
        "--",
        "-d", config.template,
        "-r", config.release,
        "-a", config.arch
    ]

    stdout, stderr, code = run_cmd(cmd, timeout=300)

    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to create container: {stderr}")

    return {"status": "created", "name": config.name}


@app.post("/vms/{name}/start")
def start_vm(name: str):
    """Start a VM or container."""
    # Try KVM
    if is_libvirt_running():
        for vm in get_virsh_vms():
            if vm["name"] == name:
                stdout, stderr, code = run_cmd(["virsh", "start", name])
                if code != 0:
                    raise HTTPException(status_code=500, detail=f"Failed to start: {stderr}")
                return {"status": "started", "name": name}

    # Try LXC
    if is_lxc_available():
        for c in get_lxc_containers():
            if c["name"] == name:
                stdout, stderr, code = run_priv(["lxc-start", "-n", name])
                if code != 0:
                    raise HTTPException(status_code=500, detail=f"Failed to start: {stderr}")
                return {"status": "started", "name": name}

    raise HTTPException(status_code=404, detail="VM not found")


def _set_lxc_autostart(name: str, on: bool) -> tuple:
    """Ecrit lxc.start.auto via le helper privilegie (edite la config root)."""
    return run_priv(["/usr/sbin/secubox-vm-autostart", name, "1" if on else "0"])


@app.post("/vms/{name}/stop")
def stop_vm(name: str, force: bool = False, hold: bool = False):
    """Stop a VM or container.

    `hold` (#1225) : un arret qui TIENT. Un `lxc-stop` seul ne desactive pas
    l'autostart — au prochain boot, `lxc.service` relance le conteneur, et
    l'operateur croit son arret ignore « par un autre superviseur ». Avec
    `hold`, on coupe AUSSI l'autostart : le conteneur reste eteint jusqu'a
    decision explicite. On l'ecrit AVANT le stop, pour qu'une course avec un
    superviseur ne le rallume pas dans l'intervalle.
    """
    # Try KVM
    if is_libvirt_running():
        for vm in get_virsh_vms():
            if vm["name"] == name:
                cmd = ["virsh", "destroy" if force else "shutdown", name]
                stdout, stderr, code = run_cmd(cmd)
                if code != 0:
                    raise HTTPException(status_code=500, detail=f"Failed to stop: {stderr}")
                return {"status": "stopped", "name": name}

    # Try LXC
    if is_lxc_available():
        for c in get_lxc_containers():
            if c["name"] == name:
                if hold:
                    _set_lxc_autostart(name, False)
                cmd = ["lxc-stop", "-n", name]
                if force:
                    cmd.append("-k")
                stdout, stderr, code = run_priv(cmd)
                if code != 0:
                    raise HTTPException(status_code=500, detail=f"Failed to stop: {stderr}")
                return {"status": "stopped", "name": name, "held": hold}

    raise HTTPException(status_code=404, detail="VM not found")


@app.post("/vms/{name}/freeze")
def freeze_vm(name: str):
    """Mettre en VEILLE un conteneur LXC (#1225) : lxc-freeze gele tous ses
    processus — zero CPU, RAM conservee, reveil instantane par unfreeze. C'est
    le pendant « sleep » que l'interface reclamait, sans perdre l'etat."""
    if is_lxc_available():
        for c in get_lxc_containers():
            if c["name"] == name:
                stdout, stderr, code = run_priv(["lxc-freeze", "-n", name])
                if code != 0:
                    raise HTTPException(status_code=500, detail=f"Failed to freeze: {stderr}")
                return {"status": "frozen", "name": name}
    raise HTTPException(status_code=404, detail="Container not found")


@app.post("/vms/{name}/unfreeze")
def unfreeze_vm(name: str):
    """REVEILLER un conteneur en veille (#1225) : lxc-unfreeze relache les
    processus geles. Instantane — la RAM n'a pas bouge."""
    if is_lxc_available():
        for c in get_lxc_containers():
            if c["name"] == name:
                stdout, stderr, code = run_priv(["lxc-unfreeze", "-n", name])
                if code != 0:
                    raise HTTPException(status_code=500, detail=f"Failed to wake: {stderr}")
                return {"status": "running", "name": name}
    raise HTTPException(status_code=404, detail="Container not found")


@app.post("/vms/{name}/autostart")
def set_autostart(name: str, on: bool = True):
    """(Dé)clarer un conteneur en DEMARRAGE AUTO (#1225). Ecrit
    `lxc.start.auto` dans sa config via un helper privilegie — le service
    tourne en `secubox` et n'ecrit pas dans /var/lib/lxc sans cela. C'est ce
    qui manquait pour que l'operateur decide qui revient au boot."""
    if is_lxc_available():
        for c in get_lxc_containers():
            if c["name"] == name:
                stdout, stderr, code = _set_lxc_autostart(name, on)
                if code != 0:
                    raise HTTPException(status_code=500,
                                        detail=f"Failed to set autostart: {stderr}")
                return {"status": "ok", "name": name, "autostart": on}
    raise HTTPException(status_code=404, detail="Container not found")


@app.post("/vms/{name}/restart")
def restart_vm(name: str):
    """Restart a VM or container."""
    # Try KVM
    if is_libvirt_running():
        for vm in get_virsh_vms():
            if vm["name"] == name:
                stdout, stderr, code = run_cmd(["virsh", "reboot", name])
                if code != 0:
                    raise HTTPException(status_code=500, detail=f"Failed to restart: {stderr}")
                return {"status": "restarted", "name": name}

    # Try LXC
    if is_lxc_available():
        for c in get_lxc_containers():
            if c["name"] == name:
                run_priv(["lxc-stop", "-n", name])
                stdout, stderr, code = run_priv(["lxc-start", "-n", name])
                if code != 0:
                    raise HTTPException(status_code=500, detail=f"Failed to restart: {stderr}")
                return {"status": "restarted", "name": name}

    raise HTTPException(status_code=404, detail="VM not found")


@app.delete("/vms/{name}")
def delete_vm(name: str):
    """Delete a VM or container."""
    # Try KVM
    if is_libvirt_running():
        for vm in get_virsh_vms():
            if vm["name"] == name:
                # Stop if running
                if 'running' in vm.get('state', '').lower():
                    run_cmd(["virsh", "destroy", name])

                # Undefine and remove storage
                stdout, stderr, code = run_cmd(["virsh", "undefine", name, "--remove-all-storage"])
                if code != 0:
                    # Try without storage removal
                    run_cmd(["virsh", "undefine", name])

                return {"status": "deleted", "name": name}

    # Try LXC
    if is_lxc_available():
        for c in get_lxc_containers():
            if c["name"] == name:
                if c.get('state') == 'running':
                    run_priv(["lxc-stop", "-n", name, "-k"])

                # lxc-destroy is intentionally NOT in the sudo grant — deleting
                # containers from an unauthenticated endpoint stays root-only.
                stdout, stderr, code = run_priv(["lxc-destroy", "-n", name])
                if code != 0:
                    raise HTTPException(status_code=500, detail=f"Failed to delete: {stderr}")

                return {"status": "deleted", "name": name}

    raise HTTPException(status_code=404, detail="VM not found")


@app.get("/vms/{name}/console")
def get_console_info(name: str):
    """Get console connection info for a VM."""
    if is_libvirt_running():
        for vm in get_virsh_vms():
            if vm["name"] == name:
                # Get VNC port
                stdout, _, code = run_cmd(["virsh", "vncdisplay", name])
                if code == 0 and stdout.strip():
                    port = 5900 + int(stdout.strip().replace(':', ''))
                    return {
                        "type": "vnc",
                        "host": "localhost",
                        "port": port,
                        "display": stdout.strip()
                    }

    if is_lxc_available():
        for c in get_lxc_containers():
            if c["name"] == name:
                return {
                    "type": "console",
                    "command": f"lxc-attach -n {name}"
                }

    raise HTTPException(status_code=404, detail="VM not found")


@app.get("/iso")
def list_iso_images():
    """List available ISO images."""
    os.makedirs(ISO_DIR, exist_ok=True)

    images = []
    for entry in os.listdir(ISO_DIR):
        if entry.endswith('.iso'):
            path = os.path.join(ISO_DIR, entry)
            stat = os.stat(path)
            images.append({
                "name": entry,
                "path": path,
                "size": stat.st_size,
                "size_human": format_size(stat.st_size)
            })

    return {"images": images}


@app.get("/templates")
def list_lxc_templates():
    """List available LXC templates."""
    templates = [
        {"name": "debian", "releases": ["bookworm", "bullseye", "buster"]},
        {"name": "ubuntu", "releases": ["jammy", "focal", "noble"]},
        {"name": "alpine", "releases": ["3.19", "3.18", "edge"]},
        {"name": "archlinux", "releases": ["current"]},
        {"name": "fedora", "releases": ["39", "38"]},
    ]
    return {"templates": templates}


def format_size(size: int) -> str:
    """Format size in human readable form."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
