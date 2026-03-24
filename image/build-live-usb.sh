#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox-DEB — build-live-usb.sh
#  Build a bootable live USB image for amd64
#  Usage: sudo bash image/build-live-usb.sh [OPTIONS]
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# ── Defaults ──────────────────────────────────────────────────────
SUITE="bookworm"
IMG_SIZE="8G"
OUT_DIR="${REPO_DIR}/output"
APT_MIRROR="http://deb.debian.org/debian"
APT_SECUBOX="https://apt.secubox.in"
USE_LOCAL_CACHE=0
SLIPSTREAM_DEBS=1              # Enabled by default - include local .deb packages
PERSISTENCE_SIZE="2G"
INCLUDE_PERSISTENCE=1
PRESEED_FILE=""

RED='\033[0;31m'; CYAN='\033[0;36m'; GOLD='\033[0;33m'
GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[live-usb]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK    ]${NC} $*"; }
err()  { echo -e "${RED}[FAIL    ]${NC} $*" >&2; exit 1; }
warn() { echo -e "${GOLD}[ WARN   ]${NC} $*"; }

# ── Parse args ────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: sudo bash build-live-usb.sh [OPTIONS]

  --suite   SUITE    Debian suite (default: bookworm)
  --out     DIR      Output directory (default: ./output)
  --size    SIZE     Total image size (default: 8G)
  --local-cache      Use local APT cache (apt-cacher-ng + local repo)
  --slipstream       Include .deb from output/debs/ in the image (default: enabled)
  --no-slipstream    Don't include local .deb packages
  --no-persistence   Don't include persistent storage partition
  --preseed FILE     Include preseed config archive (from export-preseed.sh)
  --help             Show this help

This script builds a live USB image for amd64 systems with:
  - UEFI boot support (GPT + ESP)
  - SquashFS compressed root filesystem
  - OverlayFS for runtime changes
  - Optional persistent storage partition
  - All SecuBox packages pre-installed

Output:
  secubox-live-amd64-bookworm.img     - Raw bootable image
  secubox-live-amd64-bookworm.img.gz  - Compressed image

Flash to USB:
  zcat output/secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress

EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --suite)          SUITE="$2";           shift 2 ;;
    --out)            OUT_DIR="$2";         shift 2 ;;
    --size)           IMG_SIZE="$2";        shift 2 ;;
    --local-cache)    USE_LOCAL_CACHE=1;    shift   ;;
    --slipstream)     SLIPSTREAM_DEBS=1;    shift   ;;
    --no-slipstream)  SLIPSTREAM_DEBS=0;    shift   ;;
    --no-persistence) INCLUDE_PERSISTENCE=0; shift   ;;
    --preseed)        PRESEED_FILE="$2";      shift 2 ;;
    --help|-h)        usage ;;
    *) err "Unknown argument: $1" ;;
  esac
done

# ── Checks ────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "This script must be run as root (sudo)"

# Required tools
REQUIRED_TOOLS="debootstrap parted mkfs.fat mkfs.ext4 mksquashfs rsync grub-mkrescue xorriso"
for cmd in $REQUIRED_TOOLS; do
  command -v "$cmd" >/dev/null || {
    warn "Installing missing tool: $cmd"
    apt-get install -y -qq squashfs-tools grub-efi-amd64-bin grub-pc-bin xorriso mtools dosfstools parted 2>/dev/null || true
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
  else
    warn "apt-cacher-ng not accessible — using remote mirror"
  fi

  if curl -sf "http://${LOCAL_CACHE_HOST}:${LOCAL_REPO_PORT}/dists/${SUITE}/Release" >/dev/null 2>&1; then
    APT_SECUBOX="http://${LOCAL_CACHE_HOST}:${LOCAL_REPO_PORT}"
    log "Local SecuBox repo detected: ${APT_SECUBOX}"
  else
    warn "Local SecuBox repo not accessible — fallback to apt.secubox.in"
  fi
fi

# ── Setup ─────────────────────────────────────────────────────────
mkdir -p "$OUT_DIR"
WORK_DIR=$(mktemp -d /tmp/secubox-live-XXXXXX)
ROOTFS="${WORK_DIR}/rootfs"
LIVE_DIR="${WORK_DIR}/live"
IMG_FILE="${OUT_DIR}/secubox-live-amd64-${SUITE}.img"

log "══════════════════════════════════════════════════════════"
log "Building SecuBox Live USB (amd64)"
log "Suite       : ${SUITE}"
log "Image       : ${IMG_FILE}"
log "Size        : ${IMG_SIZE}"
log "Work dir    : ${WORK_DIR}"
log "APT Mirror  : ${APT_MIRROR}"
log "SecuBox Repo: ${APT_SECUBOX}"
log "Persistence : $([[ $INCLUDE_PERSISTENCE -eq 1 ]] && echo "yes (${PERSISTENCE_SIZE})" || echo "no")"
[[ $USE_LOCAL_CACHE -eq 1 ]] && log "Local Cache : ${GREEN}enabled${NC}"
[[ $SLIPSTREAM_DEBS -eq 1 ]] && log "Slipstream  : ${GREEN}enabled${NC}"
log "══════════════════════════════════════════════════════════"

cleanup() {
  log "Cleaning up..."
  umount -lf "${ROOTFS}/proc" 2>/dev/null || true
  umount -lf "${ROOTFS}/sys"  2>/dev/null || true
  umount -lf "${ROOTFS}/dev"  2>/dev/null || true
  umount -lf "${WORK_DIR}/mnt/esp" 2>/dev/null || true
  umount -lf "${WORK_DIR}/mnt/live" 2>/dev/null || true
  umount -lf "${WORK_DIR}/mnt/persistence" 2>/dev/null || true
  umount -lf "${WORK_DIR}/mnt" 2>/dev/null || true
  [[ -n "${LOOP:-}" ]] && losetup -d "${LOOP}" 2>/dev/null || true
  rm -rf "${WORK_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

# ── Step 1: Debootstrap ───────────────────────────────────────────
log "1/8 Debootstrap ${SUITE} amd64..."
mkdir -p "${ROOTFS}"

INCLUDE_PKGS="systemd,systemd-sysv,dbus,netplan.io,nftables,openssh-server"
INCLUDE_PKGS+=",python3,python3-pip,nginx,curl,wget,ca-certificates,gnupg,apt-transport-https"
INCLUDE_PKGS+=",iproute2,iputils-ping,ethtool,net-tools,wireguard-tools"
INCLUDE_PKGS+=",sudo,less,vim-tiny,logrotate,cron,rsync,jq,dnsmasq"
INCLUDE_PKGS+=",linux-image-amd64,live-boot,live-config,live-config-systemd"
INCLUDE_PKGS+=",grub-efi-amd64,efibootmgr,pciutils,usbutils"

debootstrap --arch=amd64 \
  --include="${INCLUDE_PKGS}" \
  "${SUITE}" "${ROOTFS}" "${APT_MIRROR}"

ok "Debootstrap complete"

# ── Step 2: Base configuration ────────────────────────────────────
log "2/8 System base configuration..."

mount -t proc proc   "${ROOTFS}/proc"
mount -t sysfs sysfs "${ROOTFS}/sys"
mount --bind /dev    "${ROOTFS}/dev"

# Hostname
echo "secubox-live" > "${ROOTFS}/etc/hostname"

# /etc/hosts
cat > "${ROOTFS}/etc/hosts" <<EOF
127.0.0.1  localhost
127.0.1.1  secubox-live secubox
::1        localhost ip6-localhost ip6-loopback
EOF

# Live boot configuration
mkdir -p "${ROOTFS}/etc/live/boot.conf.d"
cat > "${ROOTFS}/etc/live/boot.conf.d/secubox.conf" <<EOF
# SecuBox Live Boot Configuration
LIVE_HOSTNAME=secubox-live
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
    eth0:
      dhcp4: true
      dhcp6: true
    enp0s3:
      dhcp4: true
    enp0s8:
      dhcp4: true
EOF

ok "Base configuration complete"

# ── Step 3: SecuBox packages ──────────────────────────────────────
log "3/8 Installing SecuBox packages..."

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
else
  warn "SecuBox APT repo not available — skip"
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

# ── Step 4: Live system scripts ───────────────────────────────────
log "4/8 Installing live system scripts..."

# Auto-start script for live boot
cat > "${ROOTFS}/usr/bin/secubox-live-init" <<'LIVESCRIPT'
#!/bin/bash
# SecuBox Live System Initialization
set -e

# Wait for network
sleep 5

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

# Enable SecuBox services
for svc in /etc/systemd/system/secubox-*.service; do
    [ -f "$svc" ] && systemctl enable "$(basename "$svc")" 2>/dev/null || true
done

# Start nginx
systemctl enable nginx
systemctl start nginx

echo "SecuBox Live System Ready"
echo "Web UI: https://$(hostname -I | awk '{print $1}'):8443"
echo "SSH: ssh root@$(hostname -I | awk '{print $1}')"
echo "Credentials: admin / admin (web) | root / secubox (ssh)"
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

# ── Install preseed system ──────────────────────────────────────
# Install preseed-apply script
mkdir -p "${ROOTFS}/usr/lib/secubox"
cp "${SCRIPT_DIR}/preseed-apply.sh" "${ROOTFS}/usr/lib/secubox/"
chmod +x "${ROOTFS}/usr/lib/secubox/preseed-apply.sh"

# Install preseed systemd service
cp "${SCRIPT_DIR}/secubox-preseed.service" "${ROOTFS}/etc/systemd/system/"
chroot "${ROOTFS}" systemctl enable secubox-preseed.service 2>/dev/null || true

# If preseed file provided, include it
if [ -n "$PRESEED_FILE" ] && [ -f "$PRESEED_FILE" ]; then
    log "Installing preseed configuration from: ${PRESEED_FILE}"
    mkdir -p "${ROOTFS}/usr/share/secubox"
    cp "$PRESEED_FILE" "${ROOTFS}/usr/share/secubox/preseed.tar.gz"
    ok "Preseed configuration included"
fi

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
  ║                    LIVE USB SYSTEM                            ║
  ║                                                               ║
  ╚═══════════════════════════════════════════════════════════════╝

  Web UI:      https://<IP>:8443
  Credentials: admin / admin
  SSH:         root / secubox  |  secubox / secubox

  For persistent storage, create a partition labeled "persistence"
  with a file "persistence.conf" containing: / union

EOF

ok "Live scripts installed"

# ── Step 5: Cleanup rootfs ────────────────────────────────────────
log "5/8 Cleaning up rootfs..."

# Clean apt cache
chroot "${ROOTFS}" apt-get clean
rm -rf "${ROOTFS}/var/lib/apt/lists"/*
rm -rf "${ROOTFS}/var/cache/apt"/*.bin
rm -rf "${ROOTFS}/tmp"/*

# Unmount special filesystems
umount -lf "${ROOTFS}/proc" 2>/dev/null || true
umount -lf "${ROOTFS}/sys"  2>/dev/null || true
umount -lf "${ROOTFS}/dev"  2>/dev/null || true

ok "Rootfs cleaned"

# ── Step 6: Create SquashFS ───────────────────────────────────────
log "6/8 Creating SquashFS filesystem..."
mkdir -p "${LIVE_DIR}/live"

mksquashfs "${ROOTFS}" "${LIVE_DIR}/live/filesystem.squashfs" \
  -comp xz -b 1M -Xdict-size 100% \
  -e boot/grub -e boot/efi

SQUASHFS_SIZE=$(du -sh "${LIVE_DIR}/live/filesystem.squashfs" | cut -f1)
ok "SquashFS created: ${SQUASHFS_SIZE}"

# Copy kernel and initrd
cp "${ROOTFS}/boot/vmlinuz-"* "${LIVE_DIR}/live/vmlinuz"
cp "${ROOTFS}/boot/initrd.img-"* "${LIVE_DIR}/live/initrd.img"

# ── Step 7: Create bootable image ─────────────────────────────────
log "7/8 Creating bootable USB image (${IMG_SIZE})..."

# Create image file
fallocate -l "${IMG_SIZE}" "${IMG_FILE}"

# Partition layout:
# 1. ESP (EFI System Partition) - 512MB
# 2. Live (SquashFS + kernel) - 4GB
# 3. Persistence (optional) - rest

if [[ $INCLUDE_PERSISTENCE -eq 1 ]]; then
  parted -s "${IMG_FILE}" \
    mklabel gpt \
    mkpart ESP fat32 1MiB 513MiB \
    mkpart LIVE fat32 513MiB 4609MiB \
    mkpart persistence ext4 4609MiB 100% \
    set 1 esp on \
    set 1 boot on
else
  parted -s "${IMG_FILE}" \
    mklabel gpt \
    mkpart ESP fat32 1MiB 513MiB \
    mkpart LIVE fat32 513MiB 100% \
    set 1 esp on \
    set 1 boot on
fi

# Setup loop device
LOOP=$(losetup -f --show -P "${IMG_FILE}")
log "Loop device: ${LOOP}"

# Format partitions
mkfs.fat -F32 -n "ESP" "${LOOP}p1"
mkfs.fat -F32 -n "LIVE" "${LOOP}p2"
if [[ $INCLUDE_PERSISTENCE -eq 1 ]]; then
  mkfs.ext4 -L "persistence" -q "${LOOP}p3"
fi

# Mount partitions
MNT="${WORK_DIR}/mnt"
mkdir -p "${MNT}/esp" "${MNT}/live"
mount "${LOOP}p1" "${MNT}/esp"
mount "${LOOP}p2" "${MNT}/live"

# Copy live system files
cp -r "${LIVE_DIR}/live" "${MNT}/live/"

# Setup GRUB EFI
mkdir -p "${MNT}/esp/EFI/BOOT" "${MNT}/esp/boot/grub" "${MNT}/esp/live"

# GRUB configuration
cat > "${MNT}/esp/boot/grub/grub.cfg" <<'EOF'
set default=0
set timeout=5

insmod all_video
insmod gfxterm
set gfxmode=auto

loadfont unicode

set menu_color_normal=cyan/black
set menu_color_highlight=white/blue

menuentry "SecuBox Live (amd64)" {
    linux /live/vmlinuz boot=live components persistence quiet splash
    initrd /live/initrd.img
}

menuentry "SecuBox Live (Safe Mode)" {
    linux /live/vmlinuz boot=live components memtest noapic noapm nodma nomce nolapic nomodeset nosmp nosplash vga=normal
    initrd /live/initrd.img
}

menuentry "SecuBox Live (No Persistence)" {
    linux /live/vmlinuz boot=live components nopersistence quiet splash
    initrd /live/initrd.img
}

menuentry "SecuBox Live (To RAM)" {
    linux /live/vmlinuz boot=live components toram quiet splash
    initrd /live/initrd.img
}

menuentry "System Shutdown" {
    halt
}

menuentry "System Restart" {
    reboot
}
EOF

# Copy kernel and initrd to ESP for GRUB access
cp "${LIVE_DIR}/live/vmlinuz" "${MNT}/esp/live/"
cp "${LIVE_DIR}/live/initrd.img" "${MNT}/esp/live/"
cp "${LIVE_DIR}/live/filesystem.squashfs" "${MNT}/live/live/"

# Install GRUB EFI bootloader
grub-mkimage -o "${MNT}/esp/EFI/BOOT/BOOTX64.EFI" \
  -O x86_64-efi \
  -p /boot/grub \
  part_gpt part_msdos fat ext2 normal linux boot configfile loopback \
  chain efifwsetup efi_gop efi_uga ls search search_label search_fs_uuid \
  search_fs_file gfxterm gfxterm_background gfxterm_menu test all_video loadenv exfat

# Copy GRUB modules
if [[ -d /usr/lib/grub/x86_64-efi ]]; then
  mkdir -p "${MNT}/esp/boot/grub/x86_64-efi"
  cp -r /usr/lib/grub/x86_64-efi/*.mod "${MNT}/esp/boot/grub/x86_64-efi/" 2>/dev/null || true
fi

# Setup persistence partition
if [[ $INCLUDE_PERSISTENCE -eq 1 ]]; then
  mkdir -p "${MNT}/persistence"
  mount "${LOOP}p3" "${MNT}/persistence"
  echo "/ union" > "${MNT}/persistence/persistence.conf"
  umount "${MNT}/persistence"
  ok "Persistence partition configured"
fi

# Unmount
sync
umount "${MNT}/esp"
umount "${MNT}/live"
losetup -d "${LOOP}"
LOOP=""

ok "Bootable image created"

# ── Step 8: Compression and checksums ─────────────────────────────
log "8/8 Compressing image..."

# Compress with gzip
gzip -9 -f "${IMG_FILE}"
IMG_GZ="${IMG_FILE}.gz"

# Generate checksum
sha256sum "${IMG_GZ}" > "${IMG_GZ}.sha256"

FINAL_SIZE=$(du -sh "${IMG_GZ}" | cut -f1)
ok "Final image: ${IMG_GZ} (${FINAL_SIZE})"

echo ""
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  SecuBox Live USB Image Ready!${NC}"
echo ""
echo -e "  Image: ${IMG_GZ}"
echo -e "  Size:  ${FINAL_SIZE}"
echo ""
echo -e "  ${BOLD}Flash to USB drive:${NC}"
echo -e "    zcat ${IMG_GZ} | sudo dd of=/dev/sdX bs=4M status=progress"
echo ""
echo -e "  ${BOLD}Boot and access:${NC}"
echo -e "    Web UI:  https://<IP>:8443 (admin / admin)"
echo -e "    SSH:     root / secubox  |  secubox / secubox"
echo ""
if [[ $INCLUDE_PERSISTENCE -eq 1 ]]; then
echo -e "  ${BOLD}Persistence:${NC}"
echo -e "    Changes are saved to the persistence partition automatically."
echo -e "    Boot with 'No Persistence' option to start fresh."
fi
echo ""
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════════${NC}"
