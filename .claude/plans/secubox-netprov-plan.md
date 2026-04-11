# Plan: secubox-netprov — Network Provisioning Module

## Overview

**secubox-netprov** is a network provisioning system for multidevice, multiplatform deployment via PXE/TFTP. It enables:

- **x64 PXE boot** (BIOS + UEFI) for PC-based installations
- **ARM64 TFTP boot** for U-Boot devices (EspressoBin, RPi)
- **Image management** for all SecuBox platforms
- **Backup/restore** of running systems
- **Fleet provisioning** for multiple devices

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     secubox-netprov                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────────┐ │
│  │   DHCP    │  │   TFTP    │  │   HTTP    │  │    FastAPI    │ │
│  │  (proxy)  │  │  (atftpd) │  │  (nginx)  │  │   (control)   │ │
│  │  :67/UDP  │  │  :69/UDP  │  │  :8080    │  │  unix socket  │ │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └───────┬───────┘ │
│        │              │              │                │         │
│        └──────────────┴──────────────┴────────────────┘         │
│                               │                                  │
│  ┌────────────────────────────▼────────────────────────────────┐│
│  │                    Image Repository                          ││
│  │  /var/lib/secubox/netprov/                                  ││
│  │  ├── images/                                                 ││
│  │  │   ├── x64/secubox-live-amd64-bookworm.img.gz             ││
│  │  │   ├── ebin-v7/secubox-espressobin-v7-bookworm.img.gz     ││
│  │  │   └── rpi400/secubox-rpi-arm64-bookworm.img.gz           ││
│  │  ├── boot/                                                   ││
│  │  │   ├── pxelinux.0 (BIOS)                                  ││
│  │  │   ├── grubnetx64.efi (UEFI)                              ││
│  │  │   ├── Image-arm64 (kernel)                               ││
│  │  │   └── initrd-arm64.img                                   ││
│  │  └── backups/                                                ││
│  │       └── <hostname>-<date>.img.gz                          ││
│  └──────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Supported Platforms

| Platform | Architecture | Boot Method | Network Protocol |
|----------|--------------|-------------|------------------|
| x64 BIOS | amd64 | PXE (pxelinux) | DHCP + TFTP |
| x64 UEFI | amd64 | PXE (GRUB EFI) | DHCP + TFTP/HTTP |
| EspressoBin V7 | arm64 | U-Boot TFTP | DHCP + TFTP |
| EspressoBin Ultra | arm64 | U-Boot TFTP | DHCP + TFTP |
| RPi 400 | arm64 | Pi firmware | DHCP + TFTP |
| MOCHAbin | arm64 | U-Boot TFTP | DHCP + TFTP |

## Components

### 1. DHCP Proxy (dnsmasq)

- Runs as DHCP proxy (not server) to coexist with existing DHCP
- Provides PXE options (next-server, boot filename)
- Detects client architecture (x86-64 BIOS/UEFI, ARM64)

```conf
# /etc/secubox/netprov/dnsmasq.d/pxe.conf
dhcp-match=set:efi-x86_64,option:client-arch,7
dhcp-match=set:efi-x86_64,option:client-arch,9
dhcp-match=set:bios,option:client-arch,0
dhcp-match=set:arm64,option:client-arch,11

dhcp-boot=tag:bios,pxelinux.0
dhcp-boot=tag:efi-x86_64,grubnetx64.efi
dhcp-boot=tag:arm64,Image-arm64

enable-tftp
tftp-root=/var/lib/secubox/netprov/boot
```

### 2. TFTP Server (atftpd)

- Serves boot files and kernels
- Supports large files for ARM64 kernel/initrd

```bash
# /etc/secubox/netprov/atftpd.conf
OPTIONS="--daemon --no-fork --port 69 /var/lib/secubox/netprov/boot"
```

### 3. HTTP Server (nginx)

- Serves large images efficiently
- Supports iPXE HTTP boot for UEFI
- Provides image download API

```nginx
# /etc/nginx/sites-available/netprov
server {
    listen 8080;
    server_name _;

    location /images/ {
        alias /var/lib/secubox/netprov/images/;
        autoindex on;
    }

    location /boot/ {
        alias /var/lib/secubox/netprov/boot/;
    }
}
```

### 4. FastAPI Control Plane

```
/api/v1/netprov/
├── GET  /status              # Service status
├── GET  /images              # List available images
├── POST /images/upload       # Upload new image
├── DELETE /images/{name}     # Remove image
├── GET  /clients             # Connected clients (DHCP leases)
├── POST /provision           # Start provisioning job
├── GET  /provision/{id}      # Job status
├── GET  /backups             # List backups
├── POST /backup              # Create backup
├── POST /restore             # Restore from backup
└── GET  /platforms           # Supported platforms
```

## File Structure

```
packages/secubox-netprov/
├── api/
│   ├── __init__.py
│   ├── main.py
│   └── routers/
│       ├── images.py
│       ├── clients.py
│       ├── provision.py
│       └── backup.py
├── www/
│   └── netprov/
│       ├── index.html
│       ├── images.html
│       ├── clients.html
│       └── backup.html
├── config/
│   ├── dnsmasq.d/
│   │   └── pxe.conf
│   ├── pxelinux.cfg/
│   │   └── default
│   └── grub/
│       └── grub.cfg
├── scripts/
│   ├── netprov-init.sh       # Initialize repository
│   ├── netprov-backup.sh     # Backup running system
│   └── netprov-restore.sh    # Restore from backup
├── menu.d/
│   └── 55-netprov.json
└── debian/
    ├── control
    ├── rules
    ├── changelog
    ├── postinst
    ├── prerm
    └── secubox-netprov.service
```

## Boot Configurations

### PXE Boot (x64 BIOS)

```
# pxelinux.cfg/default
DEFAULT secubox-live
TIMEOUT 50
PROMPT 1

LABEL secubox-live
    MENU LABEL ^SecuBox Live (x64)
    KERNEL vmlinuz-amd64
    APPEND initrd=initrd-amd64.img boot=live fetch=http://NETPROV_IP:8080/images/x64/filesystem.squashfs ip=dhcp

LABEL secubox-install
    MENU LABEL ^Install SecuBox to Disk
    KERNEL vmlinuz-amd64
    APPEND initrd=initrd-amd64.img secubox.install=auto secubox.image=http://NETPROV_IP:8080/images/x64/secubox-live-amd64-bookworm.img.gz
```

### PXE Boot (x64 UEFI)

```
# grub/grub.cfg
set timeout=10
set default=0

menuentry "SecuBox Live (x64 UEFI)" {
    linux vmlinuz-amd64 boot=live fetch=http://$pxe_default_server:8080/images/x64/filesystem.squashfs ip=dhcp
    initrd initrd-amd64.img
}

menuentry "Install SecuBox to Disk" {
    linux vmlinuz-amd64 secubox.install=auto secubox.image=http://$pxe_default_server:8080/images/x64/secubox-live-amd64-bookworm.img.gz
    initrd initrd-amd64.img
}
```

### U-Boot TFTP (EspressoBin)

```bash
# Commands for U-Boot
setenv serverip 192.168.1.100
setenv ipaddr 192.168.1.50
tftp $kernel_addr_r Image-arm64
tftp $fdt_addr_r armada-3720-espressobin-v7-emmc.dtb
tftp $ramdisk_addr_r initrd-arm64.img
setenv bootargs "boot=live fetch=http://192.168.1.100:8080/images/ebin-v7/filesystem.squashfs ip=dhcp console=ttyMV0,115200"
booti $kernel_addr_r $ramdisk_addr_r:$filesize $fdt_addr_r
```

## Backup/Restore Feature

### Backup Process

1. **Initiate** via API or CLI: `secubox-netprov backup <hostname>`
2. **Connect** to target device via SSH
3. **Create** compressed disk image: `dd | gzip | ssh`
4. **Store** in `/var/lib/secubox/netprov/backups/`
5. **Register** backup metadata in database

### Restore Process

1. **Boot** target into netboot recovery
2. **Select** backup image from menu
3. **Stream** image via HTTP: `curl | zcat | dd`
4. **Verify** with checksum
5. **Reboot** into restored system

## Web UI Features

### Dashboard (index.html)
- Service status (DHCP, TFTP, HTTP)
- Connected clients count
- Recent provisioning jobs
- Storage usage

### Images (images.html)
- List available images by platform
- Upload new images
- Generate checksums
- Delete old images

### Clients (clients.html)
- DHCP lease table
- Client architecture detection
- Provisioning history
- Real-time boot status

### Backup (backup.html)
- Scheduled backups
- Manual backup trigger
- Restore wizard
- Backup retention policy

## Dependencies

```
Depends:
 secubox-core,
 dnsmasq,
 atftpd,
 nginx,
 pxelinux,
 grub-efi-amd64-signed,
 syslinux-common,
 python3-aiofiles
```

## Security Considerations

1. **Network isolation**: Provisioning network should be separate VLAN
2. **Authentication**: API requires JWT, provisioning uses SSH keys
3. **Image integrity**: All images signed with GPG, verified at boot
4. **Access control**: Only authorized MAC addresses can provision
5. **Audit log**: All provisioning operations logged

## Implementation Steps

### Phase 1: Core Infrastructure
1. Create package structure with debian/
2. Implement FastAPI skeleton with /status
3. Configure dnsmasq PXE proxy
4. Setup TFTP with atftpd
5. Configure nginx for images

### Phase 2: x64 PXE Boot
1. Create pxelinux.cfg/default
2. Create grub.cfg for UEFI
3. Package kernel/initrd extraction
4. Test BIOS and UEFI boot

### Phase 3: ARM64 U-Boot
1. Create U-Boot boot scripts
2. Package ARM64 kernel/DTB
3. Test EspressoBin boot
4. Test RPi 400 boot

### Phase 4: Image Management
1. Implement /images API
2. Create upload/download UI
3. Add checksum verification
4. Implement storage management

### Phase 5: Backup/Restore
1. Implement backup over SSH
2. Create restore boot menu
3. Add scheduling support
4. Test full restore cycle

### Phase 6: Fleet Provisioning
1. Multi-device targeting
2. Progress tracking
3. Parallel provisioning
4. Failure handling

## CLI Commands

```bash
# Service control
systemctl status secubox-netprov

# List images
secubox-netprov images list

# Upload image
secubox-netprov images upload x64 /path/to/image.img.gz

# List connected clients
secubox-netprov clients list

# Create backup
secubox-netprov backup create <hostname>

# Restore backup
secubox-netprov backup restore <hostname> <backup-id>

# Start provisioning
secubox-netprov provision start --platform ebin-v7 --mac aa:bb:cc:dd:ee:ff
```

## Menu Definition

```json
{
  "id": "netprov",
  "name": "Network Provisioning",
  "category": "network",
  "icon": "🌐",
  "path": "/netprov/",
  "order": 350,
  "description": "PXE/TFTP network boot and system provisioning"
}
```

## Testing Plan

1. **Unit tests**: API endpoints, config parsing
2. **Integration tests**: Full boot cycle (QEMU)
3. **Hardware tests**:
   - x64 BIOS machine
   - x64 UEFI machine
   - EspressoBin V7
   - RPi 400
4. **Backup/restore tests**: Full cycle verification
