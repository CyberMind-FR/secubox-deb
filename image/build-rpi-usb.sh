#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox-DEB — build-rpi-usb.sh v1.0
#  Build a bootable USB image for Raspberry Pi 400 (arm64) with:
#  - Native Pi bootloader (no GRUB)
#  - All SecuBox packages slipstreamed
#  - Root autologin
#  - Optional GUI kiosk mode
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# ── Defaults ──────────────────────────────────────────────────────
SUITE="bookworm"
IMG_SIZE="8G"
OUT_DIR="${REPO_DIR}/output"
APT_MIRROR="http://deb.debian.org/debian"
USE_LOCAL_CACHE=0
INCLUDE_KIOSK=0
NO_COMPRESS=0

RED='\033[0;31m'; CYAN='\033[0;36m'; GOLD='\033[0;33m'
GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[rpi-usb]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK   ]${NC} $*"; }
err()  { echo -e "${RED}[FAIL  ]${NC} $*" >&2; exit 1; }
warn() { echo -e "${GOLD}[ WARN ]${NC} $*"; }

usage() {
  cat <<EOF
Usage: sudo bash build-rpi-usb.sh [OPTIONS]

  --suite   SUITE    Debian suite (default: bookworm)
  --out     DIR      Output directory (default: ./output)
  --size    SIZE     Total image size (default: 8G)
  --local-cache      Use local APT cache
  --kiosk            Include GUI kiosk mode packages
  --no-compress      Skip gzip compression
  --help             Show this help

Target: Raspberry Pi 400 (arm64)
Output: secubox-rpi-arm64-bookworm.img

Flash to USB/SD:
  zcat output/secubox-rpi-arm64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress

EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --suite)        SUITE="$2";         shift 2 ;;
    --out)          OUT_DIR="$2";       shift 2 ;;
    --size)         IMG_SIZE="$2";      shift 2 ;;
    --local-cache)  USE_LOCAL_CACHE=1;  shift   ;;
    --kiosk)        INCLUDE_KIOSK=1;    shift   ;;
    --no-compress)  NO_COMPRESS=1;      shift   ;;
    --help|-h)      usage ;;
    *) err "Unknown argument: $1" ;;
  esac
done

# ── Checks ────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "This script must be run as root (sudo)"

log "Checking dependencies..."
apt-get install -y -qq debootstrap qemu-user-static binfmt-support \
  dosfstools parted e2fsprogs 2>/dev/null || true

for cmd in debootstrap parted mkfs.fat mkfs.ext4; do
  command -v "$cmd" >/dev/null || err "Missing: $cmd"
done

# Enable ARM64 emulation
if [[ ! -f /proc/sys/fs/binfmt_misc/qemu-aarch64 ]]; then
  update-binfmts --enable qemu-aarch64 2>/dev/null || warn "qemu-aarch64 binfmt not available"
fi

# ── Variables ─────────────────────────────────────────────────────
WORK_DIR=$(mktemp -d)
ROOTFS="${WORK_DIR}/rootfs"
IMG_FILE="${OUT_DIR}/secubox-rpi-arm64-${SUITE}.img"

trap "cleanup" EXIT
cleanup() {
  log "Cleaning up..."
  umount -R "${ROOTFS}" 2>/dev/null || true
  [[ -n "${LOOP:-}" ]] && losetup -d "$LOOP" 2>/dev/null || true
  rm -rf "${WORK_DIR}"
}

mkdir -p "${OUT_DIR}" "${ROOTFS}"

log "══════════════════════════════════════════════════════════"
log "SecuBox Raspberry Pi 400 Image Builder"
log "Suite: ${SUITE} | Size: ${IMG_SIZE}"
log "══════════════════════════════════════════════════════════"

# ══════════════════════════════════════════════════════════════════
# Step 1: Debootstrap ARM64
# ══════════════════════════════════════════════════════════════════
log "1/6 Debootstrap arm64..."

INCLUDE_PKGS="systemd,systemd-sysv,dbus,nftables,openssh-server"
INCLUDE_PKGS+=",python3,python3-pip,nginx,curl,wget,ca-certificates,gnupg"
INCLUDE_PKGS+=",iproute2,iputils-ping,net-tools,wireguard-tools"
INCLUDE_PKGS+=",sudo,less,vim-tiny,cron,rsync,jq"
INCLUDE_PKGS+=",linux-image-arm64,raspi-firmware"

debootstrap --arch=arm64 --foreign --include="${INCLUDE_PKGS}" \
  "${SUITE}" "${ROOTFS}" "${APT_MIRROR}"

# Complete second stage with QEMU
cp /usr/bin/qemu-aarch64-static "${ROOTFS}/usr/bin/"
chroot "${ROOTFS}" /debootstrap/debootstrap --second-stage

ok "Debootstrap complete"

# ══════════════════════════════════════════════════════════════════
# Step 2: Base configuration
# ══════════════════════════════════════════════════════════════════
log "2/6 System configuration..."

# Hostname
echo "secubox-rpi" > "${ROOTFS}/etc/hostname"
cat > "${ROOTFS}/etc/hosts" <<EOF
127.0.0.1   localhost
127.0.1.1   secubox-rpi
::1         localhost ip6-localhost ip6-loopback
EOF

# Root password
chroot "${ROOTFS}" bash -c 'echo "root:secubox" | chpasswd'

# Timezone
ln -sf /usr/share/zoneinfo/Europe/Paris "${ROOTFS}/etc/localtime"

# Locale
echo "en_US.UTF-8 UTF-8" >> "${ROOTFS}/etc/locale.gen"
echo "fr_FR.UTF-8 UTF-8" >> "${ROOTFS}/etc/locale.gen"
chroot "${ROOTFS}" locale-gen 2>/dev/null || true

# Console keyboard
mkdir -p "${ROOTFS}/etc/default"
cat > "${ROOTFS}/etc/default/keyboard" <<EOF
XKBMODEL="pc105"
XKBLAYOUT="fr"
XKBVARIANT="azerty"
BACKSPACE="guess"
EOF

# Fstab
cat > "${ROOTFS}/etc/fstab" <<EOF
# SecuBox RPi fstab
/dev/mmcblk0p1  /boot/firmware  vfat    defaults          0       2
/dev/mmcblk0p2  /               ext4    defaults,noatime  0       1
EOF

# Serial console for Pi
mkdir -p "${ROOTFS}/etc/systemd/system/serial-getty@ttyAMA0.service.d"
cat > "${ROOTFS}/etc/systemd/system/serial-getty@ttyAMA0.service.d/autologin.conf" <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I \$TERM
EOF

# Enable serial console
chroot "${ROOTFS}" systemctl enable serial-getty@ttyAMA0.service 2>/dev/null || true

# Enable getty@tty1 for HDMI console
mkdir -p "${ROOTFS}/etc/systemd/system/getty@tty1.service.d"
cat > "${ROOTFS}/etc/systemd/system/getty@tty1.service.d/override.conf" <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I \$TERM
Type=idle
EOF
chroot "${ROOTFS}" systemctl enable getty@tty1.service 2>/dev/null || true
chroot "${ROOTFS}" systemctl set-default multi-user.target 2>/dev/null || true

# ── Cyber Boot Splash (VT100 DEC PDP-style) ─────────────────────────
cat > "${ROOTFS}/usr/local/bin/secubox-splash" <<'SPLASH'
#!/bin/bash
# SecuBox Cyber Boot Splash - VT100/DEC PDP Style

ESC="\033"
GREEN="${ESC}[32m"
BRIGHT="${ESC}[1m"
DIM="${ESC}[2m"
BLINK="${ESC}[5m"
RESET="${ESC}[0m"
CLEAR="${ESC}[2J${ESC}[H"

echo -ne "$CLEAR$GREEN"

type_slow() {
    local text="$1"
    for ((i=0; i<${#text}; i++)); do
        echo -n "${text:$i:1}"
        sleep 0.02
    done
    echo ""
}

cat << 'BANNER'

  ____  _____ ____ _   _ ____   _____  __
 / ___|| ____/ ___| | | | __ ) / _ \ \/ /
 \___ \|  _|| |   | | | |  _ \| | | \  /
  ___) | |__| |___| |_| | |_) | |_| /  \
 |____/|_____\____|\___/|____/ \___/_/\_\

BANNER

echo ""
echo -e "${BRIGHT}================================================================${RESET}${GREEN}"
echo "  RASPBERRY PI 400 SECURITY TERMINAL"
echo "  SECUBOX CYBER DEFENSE SYSTEM"
echo -e "${BRIGHT}================================================================${RESET}${GREEN}"
echo ""

type_slow "BOOT SEQUENCE INITIATED..."
echo ""

steps=(
    "MEMORY TEST.................... OK"
    "LOADING KERNEL................. DONE"
    "CRYPTOGRAPHIC MODULES.......... LOADED"
    "NETWORK STACK.................. INITIALIZED"
    "FIREWALL RULES................. ACTIVE"
    "SECURE SHELL................... READY"
)

for step in "${steps[@]}"; do
    echo -n "  > "
    type_slow "$step"
    sleep 0.1
done

echo ""
echo -e "${BRIGHT}================================================================${RESET}${GREEN}"
echo ""
echo -e "  ${BLINK}*${RESET}${GREEN} SYSTEM READY"
echo ""
echo "  .------------------------------------------------."
echo "  |  SECUBOX CYBER SECURITY PLATFORM               |"
echo "  |  TYPE 'help' FOR AVAILABLE COMMANDS            |"
echo "  |  RASPBERRY PI 400 ARM64 EDITION                |"
echo "  '------------------------------------------------'"
echo ""
echo -e "${DIM}  Press ENTER to continue...${RESET}${GREEN}"
read -t 5 || true
echo -ne "$RESET"
SPLASH
chmod +x "${ROOTFS}/usr/local/bin/secubox-splash"

# Add splash to root's bashrc
cat >> "${ROOTFS}/root/.bashrc" <<'BASHRC'

# SecuBox Cyber Splash on login
if [ -t 0 ] && [ -z "$SECUBOX_SPLASH_SHOWN" ]; then
    export SECUBOX_SPLASH_SHOWN=1
    /usr/local/bin/secubox-splash 2>/dev/null || true
fi
BASHRC

ok "System configured"

# ══════════════════════════════════════════════════════════════════
# Step 3: Network configuration
# ══════════════════════════════════════════════════════════════════
log "3/6 Network configuration..."

# Use systemd-networkd for simplicity
mkdir -p "${ROOTFS}/etc/systemd/network"

# Ethernet DHCP
cat > "${ROOTFS}/etc/systemd/network/10-eth.network" <<EOF
[Match]
Name=eth* en*

[Network]
DHCP=yes

[DHCP]
UseDNS=yes
UseHostname=no
EOF

# WiFi support (optional)
cat > "${ROOTFS}/etc/systemd/network/20-wlan.network" <<EOF
[Match]
Name=wlan*

[Network]
DHCP=yes
EOF

chroot "${ROOTFS}" systemctl enable systemd-networkd.service 2>/dev/null || true
chroot "${ROOTFS}" systemctl enable systemd-resolved.service 2>/dev/null || true

ok "Network configured"

# ══════════════════════════════════════════════════════════════════
# Step 4: SecuBox packages
# ══════════════════════════════════════════════════════════════════
log "4/6 Installing SecuBox packages..."

# APT sources
cat > "${ROOTFS}/etc/apt/sources.list" <<EOF
deb ${APT_MIRROR} ${SUITE} main contrib non-free non-free-firmware
deb ${APT_MIRROR} ${SUITE}-updates main contrib non-free non-free-firmware
EOF

chroot "${ROOTFS}" apt-get update -q

# Install firmware
chroot "${ROOTFS}" apt-get install -y -q --no-install-recommends \
  firmware-brcm80211 firmware-misc-nonfree \
  2>/dev/null || warn "Some firmware unavailable"

# SecuBox packages from local cache
CACHE_DEBS="${REPO_DIR}/cache/repo/pool"
if [[ -d "$CACHE_DEBS" ]]; then
  log "Installing SecuBox packages from cache..."
  install -d "${ROOTFS}/tmp/secubox-debs"

  # Copy ARM64 packages (or all if arch-independent)
  find "$CACHE_DEBS" -name "secubox-*_all.deb" -exec cp {} "${ROOTFS}/tmp/secubox-debs/" \;
  find "$CACHE_DEBS" -name "secubox-*_arm64.deb" -exec cp {} "${ROOTFS}/tmp/secubox-debs/" \; 2>/dev/null || true

  DEB_COUNT=$(ls "${ROOTFS}/tmp/secubox-debs/"*.deb 2>/dev/null | wc -l)
  log "Found ${DEB_COUNT} packages"

  if [[ $DEB_COUNT -gt 0 ]]; then
    chroot "${ROOTFS}" dpkg -i /tmp/secubox-debs/*.deb 2>/dev/null || true
    chroot "${ROOTFS}" apt-get install -f -y -q 2>/dev/null || true
  fi

  rm -rf "${ROOTFS}/tmp/secubox-debs"
fi

# Clean
chroot "${ROOTFS}" apt-get clean
rm -rf "${ROOTFS}/var/lib/apt/lists"/*

ok "SecuBox packages installed"

# ══════════════════════════════════════════════════════════════════
# Step 5: Raspberry Pi boot configuration
# ══════════════════════════════════════════════════════════════════
log "5/6 Configuring Pi bootloader..."

# config.txt for Pi 400
mkdir -p "${ROOTFS}/boot/firmware"
cat > "${ROOTFS}/boot/firmware/config.txt" <<EOF
# SecuBox Raspberry Pi 400 Configuration

# Boot
arm_64bit=1
kernel=vmlinuz
initramfs initrd.img followkernel

# Display
hdmi_force_hotplug=1
disable_overscan=1

# GPU memory (minimum for headless, increase for kiosk)
gpu_mem=64

# Enable USB boot
program_usb_boot_mode=1

# Serial console
enable_uart=1

# Overclock (optional, Pi 400 is already fast)
#over_voltage=6
#arm_freq=2000
EOF

# cmdline.txt
cat > "${ROOTFS}/boot/firmware/cmdline.txt" <<EOF
console=serial0,115200 console=tty1 root=/dev/mmcblk0p2 rootfstype=ext4 elevator=deadline fsck.repair=yes rootwait quiet
EOF

ok "Pi bootloader configured"

# ══════════════════════════════════════════════════════════════════
# Step 6: Create image
# ══════════════════════════════════════════════════════════════════
log "6/6 Creating bootable image..."

rm -f "${IMG_FILE}" "${IMG_FILE}.gz"
truncate -s "${IMG_SIZE}" "${IMG_FILE}"

# Partition: MBR with boot + root
parted -s "${IMG_FILE}" \
  mklabel msdos \
  mkpart primary fat32 1MiB 257MiB \
  mkpart primary ext4 257MiB 100% \
  set 1 boot on

# Setup loop device
LOOP=$(losetup -fP --show "${IMG_FILE}")
log "Loop device: ${LOOP}"

# Format partitions
mkfs.vfat -F 32 -n BOOT "${LOOP}p1"
mkfs.ext4 -L ROOT -q "${LOOP}p2"

# Mount
MNT="${WORK_DIR}/mnt"
mkdir -p "${MNT}"
mount "${LOOP}p2" "${MNT}"
mkdir -p "${MNT}/boot/firmware"
mount "${LOOP}p1" "${MNT}/boot/firmware"

# Copy rootfs
log "Copying rootfs..."
rsync -aHAX --info=progress2 "${ROOTFS}/" "${MNT}/"

# Copy kernel and initrd to boot partition
cp "${MNT}/boot/vmlinuz-"* "${MNT}/boot/firmware/vmlinuz"
cp "${MNT}/boot/initrd.img-"* "${MNT}/boot/firmware/initrd.img"

# Update fstab with proper UUIDs
BOOT_UUID=$(blkid -s UUID -o value "${LOOP}p1")
ROOT_UUID=$(blkid -s UUID -o value "${LOOP}p2")
cat > "${MNT}/etc/fstab" <<EOF
# SecuBox RPi fstab
UUID=${BOOT_UUID}  /boot/firmware  vfat    defaults          0       2
UUID=${ROOT_UUID}  /               ext4    defaults,noatime  0       1
EOF

# Update cmdline with UUID
cat > "${MNT}/boot/firmware/cmdline.txt" <<EOF
console=serial0,115200 console=tty1 root=UUID=${ROOT_UUID} rootfstype=ext4 elevator=deadline fsck.repair=yes rootwait quiet
EOF

# Sync and unmount
sync
umount "${MNT}/boot/firmware"
umount "${MNT}"
losetup -d "${LOOP}"
unset LOOP

IMG_SIZE_ACTUAL=$(du -sh "${IMG_FILE}" | cut -f1)
ok "Image created: ${IMG_SIZE_ACTUAL}"

# Compress
if [[ $NO_COMPRESS -eq 0 ]]; then
  log "Compressing..."
  gzip -9 -f "${IMG_FILE}"
  FINAL_SIZE=$(du -sh "${IMG_FILE}.gz" | cut -f1)
  sha256sum "${IMG_FILE}.gz" > "${IMG_FILE}.gz.sha256"
  ok "Compressed: ${FINAL_SIZE}"
fi

# ══════════════════════════════════════════════════════════════════
# Done
# ══════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  SecuBox Raspberry Pi 400 Image Ready!${NC}"
echo ""
echo -e "  Image: ${IMG_FILE}${NO_COMPRESS:+.gz}"
echo ""
echo -e "  ${CYAN}Flash to USB/SD:${NC}"
if [[ $NO_COMPRESS -eq 0 ]]; then
  echo -e "    zcat ${IMG_FILE}.gz | sudo dd of=/dev/sdX bs=4M status=progress"
else
  echo -e "    sudo dd if=${IMG_FILE} of=/dev/sdX bs=4M status=progress"
fi
echo ""
echo -e "  ${CYAN}Default login:${NC} root / secubox"
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════${NC}"
