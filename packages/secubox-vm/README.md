# SecuBox VM

Virtualization management module for SecuBox. Provides a unified API for managing both KVM virtual machines (via libvirt) and LXC containers.

## Features

- KVM virtual machine management via libvirt/virsh
- LXC container management
- Unified API for both virtualization types
- VM lifecycle management (create, start, stop, restart, delete)
- VNC console access for KVM VMs
- ISO image management for VM installation
- LXC template listing for container creation
- Automatic KVM hardware detection (/dev/kvm)

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /health | Health check |
| GET | /status | Virtualization status (libvirt, LXC, KVM) |
| GET | /vms | List all VMs and containers |
| GET | /vms/kvm | List KVM virtual machines only |
| GET | /vms/lxc | List LXC containers only |
| GET | /vms/{name} | Get VM or container details |
| POST | /vms/kvm | Create a new KVM VM |
| POST | /vms/lxc | Create a new LXC container |
| POST | /vms/{name}/start | Start a VM or container |
| POST | /vms/{name}/stop | Stop a VM or container (force optional) |
| POST | /vms/{name}/restart | Restart a VM or container |
| DELETE | /vms/{name} | Delete a VM or container |
| GET | /vms/{name}/console | Get console connection info |
| GET | /iso | List available ISO images |
| GET | /templates | List available LXC templates |

## Configuration

**Storage Directories:**
- `/var/lib/secubox/vm/` - VM data directory
- `/var/lib/secubox/vm/iso/` - ISO image storage
- `/var/lib/secubox/vm/disks/` - Virtual disk storage (qcow2)

**Data Models:**

```python
# KVM VM creation
{
    "name": "debian-server",
    "memory": 2048,       # MB
    "vcpus": 2,
    "disk_size": 20,      # GB
    "iso": "debian-12.iso",
    "os_type": "linux"
}

# LXC container creation
{
    "name": "web-container",
    "template": "debian",
    "release": "bookworm",
    "arch": "amd64"
}
```

## Dependencies

- python3
- python3-fastapi
- python3-pydantic
- secubox-core
- libvirt-daemon-system (for KVM)
- qemu-system (for KVM)
- qemu-utils (for qcow2 disk creation)
- virtinst (for virt-install)
- lxc (for LXC containers)
- lxc-templates (for LXC container creation)

## Files

- `/var/lib/secubox/vm/` - VM data root directory
- `/var/lib/secubox/vm/iso/` - ISO images for VM installation
- `/var/lib/secubox/vm/disks/{name}.qcow2` - Virtual machine disk images
- `/etc/secubox/vm.toml` - Module configuration

## Supported LXC Templates

- **debian**: bookworm, bullseye, buster
- **ubuntu**: jammy, focal, noble
- **alpine**: 3.19, 3.18, edge
- **archlinux**: current
- **fedora**: 39, 38

## Usage Examples

**Create a KVM VM:**
```bash
curl -X POST http://localhost/api/v1/vm/vms/kvm \
  -H "Content-Type: application/json" \
  -d '{"name": "test-vm", "memory": 4096, "vcpus": 4, "disk_size": 50}'
```

**Create an LXC container:**
```bash
curl -X POST http://localhost/api/v1/vm/vms/lxc \
  -H "Content-Type: application/json" \
  -d '{"name": "web-server", "template": "debian", "release": "bookworm"}'
```

**Start a VM:**
```bash
curl -X POST http://localhost/api/v1/vm/vms/test-vm/start
```

**Get VNC console info:**
```bash
curl http://localhost/api/v1/vm/vms/test-vm/console
# Returns: {"type": "vnc", "host": "localhost", "port": 5900, "display": ":0"}
```

**Force stop a VM:**
```bash
curl -X POST "http://localhost/api/v1/vm/vms/test-vm/stop?force=true"
```

## Requirements

- For KVM: CPU with virtualization extensions (Intel VT-x or AMD-V)
- `/dev/kvm` must be accessible
- libvirtd service must be running for KVM operations

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind - https://cybermind.fr
