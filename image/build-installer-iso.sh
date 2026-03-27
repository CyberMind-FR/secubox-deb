#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox-DEB — build-installer-iso.sh
#  Build a hybrid Live USB / Headless Installer ISO for x64
#  Usage: sudo bash image/build-installer-iso.sh [OPTIONS]
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# ── Defaults ──────────────────────────────────────────────────────
SUITE="bookworm"
OUT_DIR="${REPO_DIR}/output"
APT_MIRROR="http://deb.debian.org/debian"
APT_SECUBOX="https://apt.secubox.in"
USE_LOCAL_CACHE=0
SLIPSTREAM_DEBS=1
INCLUDE_INSTALLER=1
PRESEED_FILE=""
ISO_NAME="secubox-installer"

RED='\033[0;31m'; CYAN='\033[0;36m'; GOLD='\033[0;33m'
GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[iso-build]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK     ]${NC} $*"; }
err()  { echo -e "${RED}[FAIL     ]${NC} $*" >&2; exit 1; }
warn() { echo -e "${GOLD}[ WARN    ]${NC} $*"; }

# ── Parse args ────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: sudo bash build-installer-iso.sh [OPTIONS]

  --suite   SUITE    Debian suite (default: bookworm)
  --out     DIR      Output directory (default: ./output)
  --name    NAME     ISO name prefix (default: secubox-installer)
  --local-cache      Use local APT cache (apt-cacher-ng + local repo)
  --slipstream       Include .deb from output/debs/ in the image (default: enabled)
  --no-slipstream    Don't include local .deb packages
  --live-only        Only create live image, no installer
  --preseed FILE     Include preseed config archive
  --help             Show this help

This script builds a HYBRID ISO that can:
  1. Boot LIVE from USB (with persistence partition support)
  2. Install HEADLESSLY to disk (preseeded auto-install)
  3. Install INTERACTIVELY with minimal prompts

Output:
  secubox-installer-amd64-bookworm.iso   - Hybrid bootable ISO
  secubox-installer-amd64-bookworm.img   - Raw USB image

Boot Options at GRUB menu:
  - SecuBox Live             : Boot live system
  - SecuBox Install          : Auto-install to first disk
  - SecuBox Install (Expert) : Interactive installation

Flash to USB:
  sudo dd if=output/secubox-installer-amd64-bookworm.img of=/dev/sdX bs=4M status=progress

Burn to CD/DVD:
  sudo xorriso -as cdrecord -v dev=/dev/sr0 output/secubox-installer-amd64-bookworm.iso

EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --suite)          SUITE="$2";           shift 2 ;;
    --out)            OUT_DIR="$2";         shift 2 ;;
    --name)           ISO_NAME="$2";        shift 2 ;;
    --local-cache)    USE_LOCAL_CACHE=1;    shift   ;;
    --slipstream)     SLIPSTREAM_DEBS=1;    shift   ;;
    --no-slipstream)  SLIPSTREAM_DEBS=0;    shift   ;;
    --live-only)      INCLUDE_INSTALLER=0;  shift   ;;
    --preseed)        PRESEED_FILE="$2";    shift 2 ;;
    --help|-h)        usage ;;
    *) err "Unknown argument: $1" ;;
  esac
done

# ── Checks ────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "This script must be run as root (sudo)"

# Required tools
REQUIRED_TOOLS="debootstrap mksquashfs xorriso grub-mkrescue rsync"
for cmd in $REQUIRED_TOOLS; do
  command -v "$cmd" >/dev/null || {
    warn "Installing missing tool: $cmd"
    apt-get install -y -qq live-build squashfs-tools xorriso grub-efi-amd64-bin grub-pc-bin mtools dosfstools 2>/dev/null || true
    command -v "$cmd" >/dev/null || err "Missing required tool: $cmd"
  }
done

# ── Local cache detection ─────────────────────────────────────
if [[ $USE_LOCAL_CACHE -eq 1 ]]; then
  LOCAL_CACHE_HOST="127.0.0.1"
  LOCAL_CACHE_PORT="3142"
  LOCAL_REPO_PORT="8080"

  if curl -sf "http://${LOCAL_CACHE_HOST}:${LOCAL_CACHE_PORT}" >/dev/null 2>&1; then
    APT_MIRROR="http://${LOCAL_CACHE_HOST}:${LOCAL_CACHE_PORT}/deb.debian.org/debian"
    log "Local APT cache detected: ${APT_MIRROR}"
  fi

  if curl -sf "http://${LOCAL_CACHE_HOST}:${LOCAL_REPO_PORT}/dists/${SUITE}/Release" >/dev/null 2>&1; then
    APT_SECUBOX="http://${LOCAL_CACHE_HOST}:${LOCAL_REPO_PORT}"
    log "Local SecuBox repo detected: ${APT_SECUBOX}"
  fi
fi

# ── Setup ─────────────────────────────────────────────────────────
mkdir -p "$OUT_DIR"
WORK_DIR=$(mktemp -d /tmp/secubox-iso-XXXXXX)
ROOTFS="${WORK_DIR}/rootfs"
ISO_DIR="${WORK_DIR}/iso"
ISO_FILE="${OUT_DIR}/${ISO_NAME}-amd64-${SUITE}.iso"
IMG_FILE="${OUT_DIR}/${ISO_NAME}-amd64-${SUITE}.img"

log "══════════════════════════════════════════════════════════"
log "Building SecuBox Installer/Live ISO (amd64)"
log "Suite       : ${SUITE}"
log "ISO         : ${ISO_FILE}"
log "Work dir    : ${WORK_DIR}"
log "APT Mirror  : ${APT_MIRROR}"
log "SecuBox Repo: ${APT_SECUBOX}"
log "Installer   : $([[ $INCLUDE_INSTALLER -eq 1 ]] && echo "yes" || echo "no")"
[[ $USE_LOCAL_CACHE -eq 1 ]] && log "Local Cache : ${GREEN}enabled${NC}"
[[ $SLIPSTREAM_DEBS -eq 1 ]] && log "Slipstream  : ${GREEN}enabled${NC}"
log "══════════════════════════════════════════════════════════"

cleanup() {
  log "Cleaning up..."
  umount -lf "${ROOTFS}/proc" 2>/dev/null || true
  umount -lf "${ROOTFS}/sys"  2>/dev/null || true
  umount -lf "${ROOTFS}/dev"  2>/dev/null || true
  rm -rf "${WORK_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

# ── Step 1: Debootstrap ───────────────────────────────────────────
log "1/9 Debootstrap ${SUITE} amd64..."
mkdir -p "${ROOTFS}"

INCLUDE_PKGS="systemd,systemd-sysv,dbus,netplan.io,nftables,openssh-server"
INCLUDE_PKGS+=",python3,python3-pip,nginx,curl,wget,ca-certificates,gnupg,apt-transport-https"
INCLUDE_PKGS+=",iproute2,iputils-ping,ethtool,net-tools,wireguard-tools"
INCLUDE_PKGS+=",sudo,less,vim-tiny,logrotate,cron,rsync,jq,dnsmasq"
INCLUDE_PKGS+=",linux-image-amd64,live-boot,live-config,live-config-systemd"
INCLUDE_PKGS+=",grub-efi-amd64,grub-pc-bin,efibootmgr,pciutils,usbutils,parted,dosfstools"
# Firmware for real hardware support
INCLUDE_PKGS+=",firmware-linux-free"

debootstrap --arch=amd64 \
  --include="${INCLUDE_PKGS}" \
  "${SUITE}" "${ROOTFS}" "${APT_MIRROR}"

ok "Debootstrap complete"

# ── Step 2: Base configuration ────────────────────────────────────
log "2/9 System base configuration..."

mount -t proc proc   "${ROOTFS}/proc"
mount -t sysfs sysfs "${ROOTFS}/sys"
mount --bind /dev    "${ROOTFS}/dev"

# Hostname
echo "secubox" > "${ROOTFS}/etc/hostname"

# /etc/hosts
cat > "${ROOTFS}/etc/hosts" <<EOF
127.0.0.1  localhost
127.0.1.1  secubox
::1        localhost ip6-localhost ip6-loopback
EOF

# Live boot configuration
mkdir -p "${ROOTFS}/etc/live/boot.conf.d"
cat > "${ROOTFS}/etc/live/boot.conf.d/secubox.conf" <<EOF
LIVE_HOSTNAME=secubox
LIVE_USERNAME=secubox
LIVE_USER_FULLNAME="SecuBox User"
LIVE_USER_DEFAULT_GROUPS="audio cdrom dip floppy video plugdev netdev sudo"
PERSISTENCE=true
EOF

# Root password (secubox)
chroot "${ROOTFS}" bash -c 'echo "root:secubox" | chpasswd'

# Create secubox user
chroot "${ROOTFS}" useradd -m -s /bin/bash -G sudo secubox 2>/dev/null || true
chroot "${ROOTFS}" bash -c 'echo "secubox:secubox" | chpasswd'

# Allow sudo without password for secubox
echo "secubox ALL=(ALL) NOPASSWD: ALL" > "${ROOTFS}/etc/sudoers.d/secubox"
chmod 440 "${ROOTFS}/etc/sudoers.d/secubox"

# Enable SSH root login
sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' "${ROOTFS}/etc/ssh/sshd_config"
sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' "${ROOTFS}/etc/ssh/sshd_config"

# Timezone
echo "Europe/Paris" > "${ROOTFS}/etc/timezone"
chroot "${ROOTFS}" dpkg-reconfigure -f noninteractive tzdata 2>/dev/null || true

# Locale
chroot "${ROOTFS}" bash -c "locale-gen en_US.UTF-8 || true"
chroot "${ROOTFS}" bash -c "update-locale LANG=en_US.UTF-8 || true"

# Netplan - DHCP by default
mkdir -p "${ROOTFS}/etc/netplan"
cat > "${ROOTFS}/etc/netplan/00-live.yaml" <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    all-ethernets:
      match:
        name: "en*"
      dhcp4: true
      dhcp6: true
    eth0:
      dhcp4: true
      dhcp6: true
EOF

ok "Base configuration complete"

# Disable network-wait-online to prevent boot hang
chroot "${ROOTFS}" systemctl disable systemd-networkd-wait-online.service 2>/dev/null || true
chroot "${ROOTFS}" systemctl mask systemd-networkd-wait-online.service 2>/dev/null || true
# Also reduce timeout for NetworkManager if present
mkdir -p "${ROOTFS}/etc/systemd/system/NetworkManager-wait-online.service.d"
cat > "${ROOTFS}/etc/systemd/system/NetworkManager-wait-online.service.d/timeout.conf" <<EOF
[Service]
TimeoutStartSec=5
EOF
log "Disabled network-wait-online service"

# Mask lxc-net (causes FAILED messages on console)
chroot "${ROOTFS}" systemctl disable lxc-net.service 2>/dev/null || true
chroot "${ROOTFS}" systemctl mask lxc-net.service 2>/dev/null || true
chroot "${ROOTFS}" systemctl disable lxc.service 2>/dev/null || true
chroot "${ROOTFS}" systemctl mask lxc.service 2>/dev/null || true

# Configure systemd to not show status on console (quiet boot)
mkdir -p "${ROOTFS}/etc/systemd/system.conf.d"
cat > "${ROOTFS}/etc/systemd/system.conf.d/quiet-boot.conf" <<EOF
[Manager]
ShowStatus=no
StatusUnitFormat=name
EOF

# Remove plymouth (causes console flickering)
chroot "${ROOTFS}" apt-get remove --purge -y plymouth plymouth-label 2>/dev/null || true
chroot "${ROOTFS}" apt-get autoremove -y 2>/dev/null || true

# Disable console blanking and martian logging via kernel settings
mkdir -p "${ROOTFS}/etc/sysctl.d"
cat > "${ROOTFS}/etc/sysctl.d/99-secubox-console.conf" <<EOF
# Disable console blanking
kernel.consoleblank=0

# Disable martian packet logging (floods console)
net.ipv4.conf.all.log_martians=0
net.ipv4.conf.default.log_martians=0

# Lower kernel printk level to suppress non-critical messages
kernel.printk=1 1 1 1
EOF

# Ensure getty autologin on tty1 for live (override live-config)
mkdir -p "${ROOTFS}/etc/systemd/system/getty@tty1.service.d"
cat > "${ROOTFS}/etc/systemd/system/getty@tty1.service.d/override.conf" <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I \$TERM
Type=idle
EOF

# Disable live-config autologin (it tries to login as 'user' which doesn't exist)
mkdir -p "${ROOTFS}/etc/live/config.conf.d"
echo 'LIVE_CONFIG_NOAUTOLOGIN=true' > "${ROOTFS}/etc/live/config.conf.d/no-autologin.conf"

# Also create a 'user' account as fallback (in case live-config still triggers)
chroot "${ROOTFS}" useradd -m -s /bin/bash -G sudo user 2>/dev/null || true
echo "user:secubox" | chroot "${ROOTFS}" chpasswd

# Enable getty on tty1
chroot "${ROOTFS}" systemctl enable getty@tty1.service 2>/dev/null || true

log "Console configured (no blanking, autologin)"

# ── Step 2b: Install firmware for real hardware ───────────────────
log "2b/9 Installing firmware for hardware support..."

# Add non-free and non-free-firmware repos
cat > "${ROOTFS}/etc/apt/sources.list" <<EOF
deb ${APT_MIRROR} ${SUITE} main contrib non-free non-free-firmware
deb ${APT_MIRROR} ${SUITE}-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security ${SUITE}-security main contrib non-free non-free-firmware
EOF

chroot "${ROOTFS}" apt-get update -q

# Install firmware packages for real hardware
chroot "${ROOTFS}" apt-get install -y -q --no-install-recommends \
  firmware-linux-free \
  firmware-linux-nonfree \
  firmware-misc-nonfree \
  firmware-realtek \
  firmware-iwlwifi \
  firmware-atheros \
  firmware-brcm80211 \
  firmware-intel-sound \
  firmware-amd-graphics \
  amd64-microcode \
  intel-microcode \
  2>/dev/null || warn "Some firmware packages not available"

ok "Firmware installed"

# ── Step 3: SecuBox packages ──────────────────────────────────────
log "3/9 Installing SecuBox packages..."

# Add SecuBox repo
SECUBOX_REPO_OK=0
if [[ "$APT_SECUBOX" == "http://127.0.0.1:"* ]]; then
  if curl -sf "${APT_SECUBOX}/dists/${SUITE}/Release" >/dev/null 2>&1; then
    cat > "${ROOTFS}/etc/apt/sources.list.d/secubox.list" <<EOF
deb [trusted=yes] ${APT_SECUBOX} ${SUITE} main
EOF
    SECUBOX_REPO_OK=1
    log "Local SecuBox repo configured (trusted=yes)"
  fi
elif curl -sf "${APT_SECUBOX}/secubox-keyring.gpg" -o "${ROOTFS}/usr/share/keyrings/secubox.gpg" 2>/dev/null; then
  cat > "${ROOTFS}/etc/apt/sources.list.d/secubox.list" <<EOF
deb [signed-by=/usr/share/keyrings/secubox.gpg] ${APT_SECUBOX} ${SUITE} main
EOF
  SECUBOX_REPO_OK=1
fi

if [[ $SECUBOX_REPO_OK -eq 1 ]]; then
  chroot "${ROOTFS}" apt-get update -q
  chroot "${ROOTFS}" apt-get install -y -q secubox-full 2>/dev/null || warn "secubox-full not available"
fi

# Slipstream: integrate local .deb files
if [[ $SLIPSTREAM_DEBS -eq 1 ]]; then
  DEBS_DIR="${REPO_DIR}/output/debs"
  if [[ -d "${DEBS_DIR}" ]] && ls "${DEBS_DIR}"/*.deb >/dev/null 2>&1; then
    log "Slipstream: installing local packages..."
    install -d "${ROOTFS}/tmp/secubox-debs"
    cp "${DEBS_DIR}"/*.deb "${ROOTFS}/tmp/secubox-debs/"

    # Install secubox-core first
    if ls "${ROOTFS}/tmp/secubox-debs/secubox-core_"*.deb >/dev/null 2>&1; then
      chroot "${ROOTFS}" dpkg -i /tmp/secubox-debs/secubox-core_*.deb 2>/dev/null || true
    fi

    # Install all packages
    chroot "${ROOTFS}" dpkg -i /tmp/secubox-debs/*.deb 2>/dev/null || true
    chroot "${ROOTFS}" apt-get install -f -y -q 2>/dev/null || true

    rm -rf "${ROOTFS}/tmp/secubox-debs"
    ok "Slipstream: $(ls "${DEBS_DIR}"/*.deb 2>/dev/null | wc -l) packages installed"
  else
    warn "Slipstream: no .deb files in ${DEBS_DIR}"
  fi
fi

# Python deps
chroot "${ROOTFS}" pip3 install --break-system-packages -q \
  fastapi uvicorn[standard] python-jose[cryptography] httpx \
  jinja2 tomli pyroute2 psutil authlib aiosqlite 2>/dev/null || warn "pip install partial"

ok "Packages installed"

# ── Step 4: Installer script ──────────────────────────────────────
if [[ $INCLUDE_INSTALLER -eq 1 ]]; then
  log "4/9 Creating headless installer..."

  # Auto-installer script for headless install
  cat > "${ROOTFS}/usr/bin/secubox-installer" <<'INSTALLERSCRIPT'
#!/bin/bash
# SecuBox Headless Installer
# Automatically installs SecuBox to the first available disk

set -e

CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'
GOLD='\033[0;33m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[INSTALL]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK   ]${NC} $*"; }
err()  { echo -e "${RED}[FAIL   ]${NC} $*" >&2; exit 1; }
warn() { echo -e "${GOLD}[ WARN  ]${NC} $*"; }

echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  SecuBox Headless Installer${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
echo ""

# Detect target disk
detect_disk() {
    # Prefer NVMe, then SATA, exclude USB/removable
    for disk in /dev/nvme0n1 /dev/sda /dev/vda /dev/xvda; do
        if [ -b "$disk" ]; then
            # Skip if this is the boot device
            BOOT_DISK=$(findmnt -n -o SOURCE / 2>/dev/null | sed 's/[0-9]*$//' | sed 's/p[0-9]*$//')
            if [ "$disk" != "$BOOT_DISK" ]; then
                # Check it's not a USB drive
                if [ -d "/sys/block/$(basename $disk)" ]; then
                    REMOVABLE=$(cat "/sys/block/$(basename $disk)/removable" 2>/dev/null || echo "0")
                    if [ "$REMOVABLE" = "0" ]; then
                        echo "$disk"
                        return 0
                    fi
                fi
            fi
        fi
    done
    return 1
}

TARGET_DISK=$(detect_disk) || err "No suitable disk found for installation"
log "Target disk: ${TARGET_DISK}"

# Safety check - confirm disk is really empty or ask
DISK_SIZE=$(lsblk -b -d -n -o SIZE "$TARGET_DISK" 2>/dev/null || echo "0")
DISK_SIZE_GB=$((DISK_SIZE / 1024 / 1024 / 1024))
log "Disk size: ${DISK_SIZE_GB} GB"

# Check for headless mode (no tty)
if [ -t 0 ]; then
    # Interactive mode
    echo ""
    warn "This will ERASE ALL DATA on ${TARGET_DISK}"
    read -p "Continue? [y/N] " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]] || exit 0
else
    # Headless mode - auto proceed
    log "Headless mode: auto-installing to ${TARGET_DISK}"
    sleep 5  # Brief pause for serial console
fi

# ── Partition the disk ────────────────────────────────────────
log "Creating partitions..."

# Unmount any existing partitions
umount "${TARGET_DISK}"* 2>/dev/null || true

# Create GPT with ESP + root + data
parted -s "$TARGET_DISK" \
    mklabel gpt \
    mkpart ESP fat32 1MiB 513MiB \
    mkpart ROOT ext4 513MiB 80% \
    mkpart DATA ext4 80% 100% \
    set 1 esp on \
    set 1 boot on

# Get partition names (handle NVMe naming)
if [[ "$TARGET_DISK" == *"nvme"* ]]; then
    PART_ESP="${TARGET_DISK}p1"
    PART_ROOT="${TARGET_DISK}p2"
    PART_DATA="${TARGET_DISK}p3"
else
    PART_ESP="${TARGET_DISK}1"
    PART_ROOT="${TARGET_DISK}2"
    PART_DATA="${TARGET_DISK}3"
fi

# Wait for partitions
sleep 2
partprobe "$TARGET_DISK"

# Format partitions
log "Formatting partitions..."
mkfs.fat -F32 -n "ESP" "$PART_ESP"
mkfs.ext4 -L "rootfs" -q "$PART_ROOT"
mkfs.ext4 -L "data" -q "$PART_DATA"

ok "Partitions created"

# ── Mount and copy system ─────────────────────────────────────
log "Copying system files..."

INSTALL_MNT="/mnt/secubox-install"
mkdir -p "$INSTALL_MNT"
mount "$PART_ROOT" "$INSTALL_MNT"
mkdir -p "$INSTALL_MNT/boot/efi" "$INSTALL_MNT/data"
mount "$PART_ESP" "$INSTALL_MNT/boot/efi"

# Copy the running live system
rsync -ax --exclude={"/proc/*","/sys/*","/dev/*","/run/*","/tmp/*","/mnt/*","/media/*"} \
    / "$INSTALL_MNT/"

ok "System files copied"

# ── Configure installed system ────────────────────────────────
log "Configuring installed system..."

# fstab
cat > "$INSTALL_MNT/etc/fstab" <<FSTAB
# SecuBox fstab - generated by installer
UUID=$(blkid -s UUID -o value "$PART_ROOT")  /          ext4  defaults,noatime,commit=60  0  1
UUID=$(blkid -s UUID -o value "$PART_ESP")   /boot/efi  vfat  umask=0077                  0  0
UUID=$(blkid -s UUID -o value "$PART_DATA")  /data      ext4  defaults,noatime            0  2
tmpfs                                        /run/secubox tmpfs mode=0755               0  0
FSTAB

# Remove live-boot packages markers
rm -f "$INSTALL_MNT/etc/live" 2>/dev/null || true

# Set hostname
echo "secubox-$(date +%s | tail -c 5)" > "$INSTALL_MNT/etc/hostname"

# Install GRUB
log "Installing GRUB bootloader..."
mount --bind /dev "$INSTALL_MNT/dev"
mount --bind /proc "$INSTALL_MNT/proc"
mount --bind /sys "$INSTALL_MNT/sys"

chroot "$INSTALL_MNT" grub-install --target=x86_64-efi \
    --efi-directory=/boot/efi \
    --bootloader-id=secubox \
    --no-nvram --removable

chroot "$INSTALL_MNT" update-grub

# Enable firstboot service
chroot "$INSTALL_MNT" systemctl enable secubox-firstboot.service 2>/dev/null || true

# Cleanup
umount "$INSTALL_MNT/sys"
umount "$INSTALL_MNT/proc"
umount "$INSTALL_MNT/dev"
umount "$INSTALL_MNT/boot/efi"
umount "$INSTALL_MNT"

ok "Installation complete!"

echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  SecuBox Installation Complete!${NC}"
echo ""
echo -e "  Installed to: ${TARGET_DISK}"
echo ""
echo -e "  ${BOLD}On first boot:${NC}"
echo -e "    - SSH keys will be generated"
echo -e "    - Web UI will be available at https://<IP>:8443"
echo ""
echo -e "  ${BOLD}Default credentials:${NC}"
echo -e "    SSH:    root / secubox"
echo -e "    Web UI: admin / admin"
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
echo ""

# Auto reboot in headless mode
if [ ! -t 0 ]; then
    log "Rebooting in 10 seconds..."
    sleep 10
    reboot
else
    read -p "Press ENTER to reboot, or Ctrl+C to stay in live system..."
    reboot
fi
INSTALLERSCRIPT
  chmod +x "${ROOTFS}/usr/bin/secubox-installer"

  ok "Installer script created"
else
  log "4/9 Skipping installer (--live-only)"
fi

# ── Step 5: Live system scripts ───────────────────────────────────
log "5/9 Installing live system scripts..."

# Auto-start script for live boot
cat > "${ROOTFS}/usr/bin/secubox-live-init" <<'LIVESCRIPT'
#!/bin/bash
# SecuBox Live System Initialization
set -e

# Wait for network
sleep 3

# Generate SSH host keys if missing
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    ssh-keygen -A
    systemctl restart sshd
fi

# Generate JWT secret if missing
if [ ! -f /etc/secubox/jwt.secret ]; then
    mkdir -p /etc/secubox
    openssl rand -hex 32 > /etc/secubox/jwt.secret
    chmod 600 /etc/secubox/jwt.secret
fi

# Create default admin user for web UI
if [ ! -f /etc/secubox/users.json ]; then
    mkdir -p /etc/secubox
    HASH=$(echo -n "admin" | sha256sum | cut -d' ' -f1)
    cat > /etc/secubox/users.json <<EOF
{
  "admin": {
    "password_hash": "${HASH}",
    "role": "admin",
    "enabled": true
  }
}
EOF
    chmod 600 /etc/secubox/users.json
fi

# Create runtime directory
mkdir -p /run/secubox
chmod 755 /run/secubox

# Skip enabling services on live boot - they are masked for stability
# Services will be enabled after installation to disk

# Start nginx if not masked
if ! systemctl is-enabled nginx 2>/dev/null | grep -q masked; then
    systemctl enable nginx 2>/dev/null || true
    systemctl start nginx 2>/dev/null || true
fi

# Get IP address
IP=$(hostname -I | awk '{print $1}')
[ -z "$IP" ] && IP="<IP>"

echo ""
echo "SecuBox Live System Ready"
echo "========================="
echo ""
echo "Web UI: https://${IP}:8443"
echo "SSH:    ssh root@${IP}"
echo ""
echo "Credentials:"
echo "  SSH:    root / secubox  |  secubox / secubox"
echo "  Web UI: admin / admin"
echo ""
echo "To install to disk: sudo secubox-installer"
echo ""
LIVESCRIPT
chmod +x "${ROOTFS}/usr/bin/secubox-live-init"

# Systemd service for live init
cat > "${ROOTFS}/etc/systemd/system/secubox-live-init.service" <<EOF
[Unit]
Description=SecuBox Live System Initialization
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/secubox-live-init
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

chroot "${ROOTFS}" systemctl enable secubox-live-init.service

# Install preseed system
mkdir -p "${ROOTFS}/usr/lib/secubox"
if [ -f "${SCRIPT_DIR}/preseed-apply.sh" ]; then
  cp "${SCRIPT_DIR}/preseed-apply.sh" "${ROOTFS}/usr/lib/secubox/"
  chmod +x "${ROOTFS}/usr/lib/secubox/preseed-apply.sh"
fi

if [ -f "${SCRIPT_DIR}/secubox-preseed.service" ]; then
  cp "${SCRIPT_DIR}/secubox-preseed.service" "${ROOTFS}/etc/systemd/system/"
  chroot "${ROOTFS}" systemctl enable secubox-preseed.service 2>/dev/null || true
fi

# If preseed file provided, include it
if [ -n "$PRESEED_FILE" ] && [ -f "$PRESEED_FILE" ]; then
    log "Installing preseed configuration from: ${PRESEED_FILE}"
    mkdir -p "${ROOTFS}/usr/share/secubox"
    cp "$PRESEED_FILE" "${ROOTFS}/usr/share/secubox/preseed.tar.gz"
    ok "Preseed configuration included"
fi

# ── Disable services that cause restart loops on live boot ───────
# These services require configs/dependencies that don't exist on live
# They will be enabled after proper installation to disk
log "Disabling services incompatible with live boot..."

DISABLE_ON_LIVE=(
    secubox-haproxy
    secubox-zkp
    secubox-nac
    secubox-crowdsec
    secubox-dpi
    secubox-qos
    secubox-mediaflow
    secubox-cdn
    secubox-vhost
    secubox-netmodes
    secubox-auth
    secuboxd
    lxc-net
    lxc
)

for svc in "${DISABLE_ON_LIVE[@]}"; do
    chroot "${ROOTFS}" systemctl disable "${svc}.service" 2>/dev/null || true
    chroot "${ROOTFS}" systemctl mask "${svc}.service" 2>/dev/null || true
done
ok "Masked ${#DISABLE_ON_LIVE[@]} services for live boot stability"

# Welcome message
cat > "${ROOTFS}/etc/motd" <<'EOF'

  ╔═══════════════════════════════════════════════════════════════╗
  ║                                                               ║
  ║   ███████╗███████╗ ██████╗██╗   ██╗██████╗  ██████╗ ██╗  ██╗  ║
  ║   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔═══██╗╚██╗██╔╝  ║
  ║   ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║ ╚███╔╝   ║
  ║   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║ ██╔██╗   ║
  ║   ███████║███████╗╚██████╗╚██████╔╝██████╔╝╚██████╔╝██╔╝ ██╗  ║
  ║   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝  ║
  ║                                                               ║
  ║            INSTALLER / LIVE USB  (amd64)                      ║
  ║                                                               ║
  ╚═══════════════════════════════════════════════════════════════╝

  LIVE MODE:
    Web UI:  https://<IP>:8443  (admin / admin)
    SSH:     root / secubox  |  secubox / secubox

  TO INSTALL TO DISK:
    sudo secubox-installer

  For persistent storage in live mode, create a partition labeled
  "persistence" with a file "persistence.conf" containing: / union

EOF

ok "Live scripts installed"

# ── Step 6: Cleanup rootfs ────────────────────────────────────────
log "6/9 Cleaning up rootfs..."

# Clean apt cache
chroot "${ROOTFS}" apt-get clean
rm -rf "${ROOTFS}/var/lib/apt/lists"/*
rm -rf "${ROOTFS}/var/cache/apt"/*.bin
rm -rf "${ROOTFS}/tmp"/*

# Remove QEMU if present
rm -f "${ROOTFS}/usr/bin/qemu-"*-static 2>/dev/null || true

# Unmount special filesystems
umount -lf "${ROOTFS}/proc" 2>/dev/null || true
umount -lf "${ROOTFS}/sys"  2>/dev/null || true
umount -lf "${ROOTFS}/dev"  2>/dev/null || true

ok "Rootfs cleaned"

# ── Step 7: Create SquashFS ───────────────────────────────────────
log "7/9 Creating SquashFS filesystem..."
mkdir -p "${ISO_DIR}/live"

mksquashfs "${ROOTFS}" "${ISO_DIR}/live/filesystem.squashfs" \
  -comp xz -b 1M -Xdict-size 100% \
  -e boot/grub -e boot/efi

SQUASHFS_SIZE=$(du -sh "${ISO_DIR}/live/filesystem.squashfs" | cut -f1)
ok "SquashFS created: ${SQUASHFS_SIZE}"

# Copy kernel and initrd
cp "${ROOTFS}/boot/vmlinuz-"* "${ISO_DIR}/live/vmlinuz"
cp "${ROOTFS}/boot/initrd.img-"* "${ISO_DIR}/live/initrd.img"

# ── Step 8: Create GRUB ISO ───────────────────────────────────────
log "8/9 Creating bootable ISO..."

# Create GRUB config
mkdir -p "${ISO_DIR}/boot/grub"

if [[ $INCLUDE_INSTALLER -eq 1 ]]; then
  # Full menu with install options
  cat > "${ISO_DIR}/boot/grub/grub.cfg" <<'EOF'
set default=0
set timeout=10

insmod all_video
insmod gfxterm
set gfxmode=auto

loadfont unicode

set menu_color_normal=cyan/black
set menu_color_highlight=white/blue

menuentry "SecuBox Live (Default)" {
    linux /live/vmlinuz boot=live components persistence consoleblank=0 plymouth.enable=0 loglevel=1 usbcore.autosuspend=-1 libata.force=noncq
    initrd /live/initrd.img
}

menuentry "SecuBox Install (Headless Auto-Install)" {
    linux /live/vmlinuz boot=live components toram systemd.unit=secubox-installer.target consoleblank=0 plymouth.enable=0 loglevel=1 usbcore.autosuspend=-1 libata.force=noncq
    initrd /live/initrd.img
}

menuentry "SecuBox Live (No Persistence)" {
    linux /live/vmlinuz boot=live components nopersistence consoleblank=0 plymouth.enable=0 loglevel=1 usbcore.autosuspend=-1 libata.force=noncq
    initrd /live/initrd.img
}

menuentry "SecuBox Live (To RAM)" {
    linux /live/vmlinuz boot=live components toram consoleblank=0 plymouth.enable=0 loglevel=1 usbcore.autosuspend=-1 libata.force=noncq
    initrd /live/initrd.img
}

menuentry "SecuBox Live (Safe Mode)" {
    linux /live/vmlinuz boot=live components nomodeset nosplash consoleblank=0 plymouth.enable=0 loglevel=1 libata.force=noncq vga=normal
    initrd /live/initrd.img
}

menuentry "SecuBox Debug (Rescue Shell)" {
    linux /live/vmlinuz boot=live components systemd.unit=rescue.target consoleblank=0 plymouth.enable=0 loglevel=1 libata.force=noncq nomodeset
    initrd /live/initrd.img
}

menuentry "SecuBox Debug (Emergency Shell)" {
    linux /live/vmlinuz boot=live components systemd.unit=emergency.target consoleblank=0 plymouth.enable=0 loglevel=1 libata.force=noncq
    initrd /live/initrd.img
}

menuentry "SecuBox Debug (No Preseed)" {
    linux /live/vmlinuz boot=live components systemd.mask=secubox-preseed.service consoleblank=0 plymouth.enable=0 loglevel=1 libata.force=noncq
    initrd /live/initrd.img
}

menuentry "SecuBox Minimal (No Services)" {
    linux /live/vmlinuz boot=live components systemd.mask=secubox-preseed.service systemd.mask=secubox-live-init.service systemd.mask=nginx.service systemd.mask=haproxy.service consoleblank=0 plymouth.enable=0 loglevel=1 libata.force=noncq
    initrd /live/initrd.img
}

menuentry "System Shutdown" {
    halt
}

menuentry "System Restart" {
    reboot
}
EOF
else
  # Live-only menu
  cat > "${ISO_DIR}/boot/grub/grub.cfg" <<'EOF'
set default=0
set timeout=5

insmod all_video
insmod gfxterm
set gfxmode=auto

loadfont unicode

set menu_color_normal=cyan/black
set menu_color_highlight=white/blue

menuentry "SecuBox Live (Default)" {
    linux /live/vmlinuz boot=live components persistence consoleblank=0 plymouth.enable=0 loglevel=1 usbcore.autosuspend=-1 libata.force=noncq
    initrd /live/initrd.img
}

menuentry "SecuBox Live (No Persistence)" {
    linux /live/vmlinuz boot=live components nopersistence consoleblank=0 plymouth.enable=0 loglevel=1 usbcore.autosuspend=-1 libata.force=noncq
    initrd /live/initrd.img
}

menuentry "SecuBox Live (To RAM)" {
    linux /live/vmlinuz boot=live components toram consoleblank=0 plymouth.enable=0 loglevel=1 usbcore.autosuspend=-1 libata.force=noncq
    initrd /live/initrd.img
}

menuentry "System Shutdown" {
    halt
}
EOF
fi

# Create installer target (systemd)
if [[ $INCLUDE_INSTALLER -eq 1 ]]; then
  mkdir -p "${ROOTFS}/etc/systemd/system"
  cat > "${ROOTFS}/etc/systemd/system/secubox-installer.target" <<EOF
[Unit]
Description=SecuBox Auto-Installer Target
Requires=basic.target
After=basic.target network-online.target
AllowIsolate=yes

[Install]
Also=secubox-autoinstall.service
EOF

  cat > "${ROOTFS}/etc/systemd/system/secubox-autoinstall.service" <<EOF
[Unit]
Description=SecuBox Automatic Installation
After=network-online.target
Wants=network-online.target
ConditionKernelCommandLine=systemd.unit=secubox-installer.target

[Service]
Type=oneshot
ExecStart=/usr/bin/secubox-installer
StandardInput=null
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=secubox-installer.target
EOF
fi

# Build GRUB EFI image
mkdir -p "${ISO_DIR}/EFI/BOOT"

grub-mkimage -o "${ISO_DIR}/EFI/BOOT/BOOTX64.EFI" \
  -O x86_64-efi \
  -p /boot/grub \
  part_gpt part_msdos fat ext2 normal linux boot configfile loopback \
  chain efifwsetup efi_gop efi_uga ls search search_label search_fs_uuid \
  search_fs_file gfxterm gfxterm_background gfxterm_menu test all_video loadenv exfat \
  iso9660

# Copy GRUB modules
if [[ -d /usr/lib/grub/x86_64-efi ]]; then
  mkdir -p "${ISO_DIR}/boot/grub/x86_64-efi"
  cp -r /usr/lib/grub/x86_64-efi/*.mod "${ISO_DIR}/boot/grub/x86_64-efi/" 2>/dev/null || true
fi

# Create EFI boot image for ISO
dd if=/dev/zero of="${ISO_DIR}/boot/grub/efi.img" bs=1M count=10
mkfs.fat -F12 "${ISO_DIR}/boot/grub/efi.img"
mmd -i "${ISO_DIR}/boot/grub/efi.img" ::/EFI
mmd -i "${ISO_DIR}/boot/grub/efi.img" ::/EFI/BOOT
mcopy -i "${ISO_DIR}/boot/grub/efi.img" "${ISO_DIR}/EFI/BOOT/BOOTX64.EFI" ::/EFI/BOOT/

# Create BIOS boot image
grub-mkimage -o "${ISO_DIR}/boot/grub/bios.img" \
  -O i386-pc \
  -p /boot/grub \
  biosdisk part_gpt part_msdos fat ext2 normal linux boot configfile loopback \
  chain ls search search_label search_fs_uuid search_fs_file test iso9660

# Build the hybrid ISO
xorriso -as mkisofs \
  -o "${ISO_FILE}" \
  -isohybrid-mbr /usr/lib/grub/i386-pc/boot_hybrid.img \
  -c boot/grub/boot.cat \
  -b boot/grub/bios.img \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
  -eltorito-alt-boot \
  -e boot/grub/efi.img \
    -no-emul-boot -isohybrid-gpt-basdat \
  -r -J -joliet-long \
  -V "SECUBOX" \
  "${ISO_DIR}"

ok "ISO created: ${ISO_FILE}"

# ── Step 9: Create USB image ──────────────────────────────────────
log "9/9 Creating USB image..."

# Also create a raw USB image for dd
ISO_SIZE=$(stat -c %s "${ISO_FILE}")
IMG_SIZE_BYTES=$((ISO_SIZE + 512*1024*1024))  # ISO + 512MB for persistence

# Round up to nearest 4MB
IMG_SIZE_BYTES=$(( (IMG_SIZE_BYTES + 4*1024*1024 - 1) / (4*1024*1024) * 4*1024*1024 ))

fallocate -l "${IMG_SIZE_BYTES}" "${IMG_FILE}"

# Create partition layout: ISO hybrid + persistence
parted -s "${IMG_FILE}" \
  mklabel gpt \
  mkpart ISO fat32 1MiB $((ISO_SIZE/1024/1024 + 100))MiB \
  mkpart persistence ext4 $((ISO_SIZE/1024/1024 + 100))MiB 100%

# Write ISO to first partition area
dd if="${ISO_FILE}" of="${IMG_FILE}" bs=4M conv=notrunc

ok "USB image created: ${IMG_FILE}"

# Generate checksums
sha256sum "${ISO_FILE}" > "${ISO_FILE}.sha256"
sha256sum "${IMG_FILE}" > "${IMG_FILE}.sha256"

ISO_FINAL_SIZE=$(du -sh "${ISO_FILE}" | cut -f1)
IMG_FINAL_SIZE=$(du -sh "${IMG_FILE}" | cut -f1)

echo ""
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  SecuBox Installer/Live ISO Ready!${NC}"
echo ""
echo -e "  ISO: ${ISO_FILE} (${ISO_FINAL_SIZE})"
echo -e "  IMG: ${IMG_FILE} (${IMG_FINAL_SIZE})"
echo ""
echo -e "  ${BOLD}Write to USB:${NC}"
echo -e "    sudo dd if=${IMG_FILE} of=/dev/sdX bs=4M status=progress"
echo ""
echo -e "  ${BOLD}Burn to CD/DVD:${NC}"
echo -e "    xorriso -as cdrecord -v dev=/dev/sr0 ${ISO_FILE}"
echo ""
echo -e "  ${BOLD}Boot options:${NC}"
if [[ $INCLUDE_INSTALLER -eq 1 ]]; then
echo -e "    - SecuBox Live           : Boot live system"
echo -e "    - SecuBox Install        : Auto-install to first disk (headless)"
fi
echo -e "    - SecuBox Live (To RAM)  : Load entire system to RAM"
echo ""
echo -e "  ${BOLD}Default credentials:${NC}"
echo -e "    SSH:    root / secubox  |  secubox / secubox"
echo -e "    Web UI: admin / admin"
echo ""
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════════${NC}"
