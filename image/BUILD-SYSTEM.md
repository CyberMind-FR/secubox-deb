# SecuBox-DEB Modular Build System

## Architecture Overview

```
image/
├── build-secubox.sh          # Unified entry point
├── lib/
│   ├── common.sh             # Core utilities, logging, cleanup
│   ├── debootstrap.sh        # Base system installation
│   ├── packages.sh           # Package installation (apt, pip, slipstream)
│   ├── kiosk.sh              # Kiosk/X11 setup
│   └── bootloader.sh         # GRUB/U-Boot configuration
├── profiles/
│   ├── x64-vm.conf           # VM image profile
│   ├── x64-live.conf         # Live USB with kiosk
│   ├── rpi400.conf           # Raspberry Pi 400
│   ├── espressobin-v7.conf   # ESPRESSObin v7
│   └── mochabin.conf         # MOCHAbin (future)
└── splash/
    ├── boot.png              # Plymouth/X11 splash
    ├── tui-splash.sh         # Terminal ANSI splash
    └── kiosk-loading.sh      # Kiosk loading animation
```

## Usage

```bash
# Build specific profile
./image/build-secubox.sh --profile x64-vm

# Build with options
./image/build-secubox.sh --profile x64-live --kiosk --slipstream

# Build with custom SecuBox modules
SECUBOX_PROFILE=network ./image/build-secubox.sh --profile rpi400

# Build without compression
./image/build-secubox.sh --profile espressobin-v7 --no-compress
```

## Profile Variables

### Required
| Variable | Description | Example |
|----------|-------------|---------|
| `PROFILE_NAME` | Unique identifier | `x64-live` |
| `TARGET_ARCH` | CPU architecture | `amd64`, `arm64` |
| `IMAGE_NAME` | Output filename | `secubox-live.img` |
| `IMAGE_SIZE` | Disk size | `8G` |
| `PARTITION_TYPE` | Partition scheme | `efi`, `rpi` |

### Optional
| Variable | Default | Description |
|----------|---------|-------------|
| `INCLUDE_KIOSK` | `0` | Install X11/Chromium kiosk |
| `INCLUDE_SLIPSTREAM` | `0` | Install SecuBox .deb packages |
| `SECUBOX_PROFILE` | `full` | Module selection: `full`, `lite`, `network`, `custom` |
| `GRUB_TIMEOUT` | `3` | Boot menu timeout |

### Hooks
- `post_install_hook()` - Called after base system install
- `pre_package_hook()` - Called before package installation
- `post_package_hook()` - Called after package installation

## SecuBox Module Profiles

### full (default)
All 120+ SecuBox modules. Best for full-featured deployments.

### lite
Essential modules only:
- secubox-core
- secubox-hub
- secubox-crowdsec
- secubox-netdata
- secubox-wireguard
- secubox-system

### network
Network security focused:
- All lite modules plus:
- secubox-nac
- secubox-netmodes
- secubox-dpi
- secubox-waf
- secubox-dns
- secubox-qos

### custom
Use `SECUBOX_MODULES` environment variable:
```bash
SECUBOX_MODULES="secubox-core secubox-hub secubox-crowdsec" \
  ./image/build-secubox.sh --profile x64-vm
```

## Quality Checklist

### Pre-Build
- [ ] All SecuBox packages built without errors
- [ ] Package dependencies use `| python3-pip` alternatives
- [ ] Splash screens present in `image/splash/`
- [ ] Profile exists for target

### Post-Build
- [ ] Image boots in QEMU/target hardware
- [ ] SSH accessible (root/secubox)
- [ ] nginx running
- [ ] SecuBox web UI accessible at https://localhost/
- [ ] All requested modules installed (`dpkg -l | grep secubox`)

### Verification Commands
```bash
# Check packages installed in image
sudo losetup -fP output/secubox-*.img
sudo mount /dev/loop0p2 /mnt
ls /mnt/var/lib/dpkg/info/secubox*.list | wc -l
sudo umount /mnt
sudo losetup -D

# Test in QEMU
qemu-system-x86_64 -m 4096 -enable-kvm -cpu host -smp 4 \
  -drive file=output/secubox-vm-x64-bookworm.img,format=raw,if=virtio \
  -bios /usr/share/ovmf/OVMF.fd \
  -net nic,model=virtio \
  -net user,hostfwd=tcp::9443-:443,hostfwd=tcp::2222-:22 \
  -display gtk

# SSH verification
ssh -p 2222 root@localhost "dpkg -l | grep secubox | wc -l"
```

## Dependency Resolution

Python packages not in Debian repos:
- `python3-fastapi` → pip install fastapi
- `python3-uvicorn` → pip install uvicorn[standard]
- `python3-httpx` → pip install httpx

Package `control` files should use:
```
Depends: python3-uvicorn | python3-pip
```

This allows installation to succeed when pip-installed packages satisfy the dependency.

## Build Phases

1. **Initialize** - Parse options, load profile, setup cleanup
2. **Create Image** - Allocate disk, partition, format
3. **Debootstrap** - Install minimal Debian base
4. **Configure Base** - APT sources, locales, network
5. **Install Packages** - apt, pip, slipstream SecuBox
6. **Configure Services** - nginx, systemd units
7. **Install Kiosk** (optional) - X11, Chromium, nodm
8. **Install Bootloader** - GRUB or RPi firmware
9. **Finalize** - Cleanup, compress, checksum

## Error Handling

- All operations use `|| die "message"` pattern
- Cleanup stack ensures proper resource release
- Loop devices and mounts tracked for cleanup
- Build logs written to `/tmp/build-${PROFILE_NAME}.log`
