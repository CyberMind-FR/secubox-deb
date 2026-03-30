#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox-DEB — build-live-usb.sh v2.0
#  Build a bootable live USB image for amd64 with:
#  - UEFI + Legacy BIOS hybrid boot
#  - All SecuBox packages slipstreamed
#  - Root autologin
#  - Optional GUI kiosk mode
#  - Network auto-detection
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
SLIPSTREAM_DEBS=1
INCLUDE_PERSISTENCE=1
INCLUDE_KIOSK=0
PRESEED_FILE=""
NO_COMPRESS=0

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
  --local-cache      Use local APT cache
  --kiosk            Include GUI kiosk mode packages
  --no-persistence   Don't include persistent storage partition
  --no-compress      Skip gzip compression (faster, for local testing)
  --preseed FILE     Include preseed config archive
  --help             Show this help

Features:
  - UEFI + Legacy BIOS boot
  - All SecuBox packages pre-installed
  - Root autologin on console
  - Network auto-detection at first boot
  - Optional kiosk mode (--kiosk)

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
    --kiosk)          INCLUDE_KIOSK=1;      shift   ;;
    --no-persistence) INCLUDE_PERSISTENCE=0; shift   ;;
    --no-compress)    NO_COMPRESS=1;        shift   ;;
    --preseed)        PRESEED_FILE="$2";    shift 2 ;;
    --help|-h)        usage ;;
    *) err "Unknown argument: $1" ;;
  esac
done

# ── Checks ────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "This script must be run as root (sudo)"

# Required tools
log "Checking dependencies..."
apt-get install -y -qq debootstrap squashfs-tools grub-efi-amd64-bin grub-pc-bin \
  xorriso mtools dosfstools parted e2fsprogs live-boot 2>/dev/null || true

for cmd in debootstrap parted mkfs.fat mkfs.ext4 mksquashfs grub-mkimage; do
  command -v "$cmd" >/dev/null || err "Missing: $cmd"
done

# ── Local cache detection ─────────────────────────────────────
if [[ $USE_LOCAL_CACHE -eq 1 ]]; then
  if curl -sf "http://127.0.0.1:3142" >/dev/null 2>&1; then
    APT_MIRROR="http://127.0.0.1:3142/deb.debian.org/debian"
    log "Using apt-cacher-ng"
  fi
  if curl -sf "http://127.0.0.1:8080/dists/${SUITE}/Release" >/dev/null 2>&1; then
    APT_SECUBOX="http://127.0.0.1:8080"
    log "Using local SecuBox repo"
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
log "Kiosk       : $([[ $INCLUDE_KIOSK -eq 1 ]] && echo "yes" || echo "no")"
log "══════════════════════════════════════════════════════════"

cleanup() {
  log "Cleaning up..."
  umount -lf "${ROOTFS}/proc" 2>/dev/null || true
  umount -lf "${ROOTFS}/sys"  2>/dev/null || true
  umount -lf "${ROOTFS}/dev"  2>/dev/null || true
  umount -lf "${WORK_DIR}/mnt/"* 2>/dev/null || true
  [[ -n "${LOOP:-}" ]] && losetup -d "${LOOP}" 2>/dev/null || true
  rm -rf "${WORK_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

# ══════════════════════════════════════════════════════════════════
# Step 1: Debootstrap
# ══════════════════════════════════════════════════════════════════
log "1/8 Debootstrap ${SUITE} amd64..."
mkdir -p "${ROOTFS}"

INCLUDE_PKGS="systemd,systemd-sysv,dbus,netplan.io,nftables,openssh-server"
INCLUDE_PKGS+=",python3,python3-pip,nginx,curl,wget,ca-certificates,gnupg"
INCLUDE_PKGS+=",iproute2,iputils-ping,ethtool,net-tools,wireguard-tools"
INCLUDE_PKGS+=",sudo,less,vim-tiny,logrotate,cron,rsync,jq,dnsmasq"
INCLUDE_PKGS+=",linux-image-amd64,live-boot,live-boot-initramfs-tools,live-config,live-config-systemd,initramfs-tools"
INCLUDE_PKGS+=",grub-efi-amd64,efibootmgr,pciutils,usbutils,lsb-release"

debootstrap --arch=amd64 --include="${INCLUDE_PKGS}" \
  "${SUITE}" "${ROOTFS}" "${APT_MIRROR}"

ok "Debootstrap complete"

# ══════════════════════════════════════════════════════════════════
# Step 2: Base configuration
# ══════════════════════════════════════════════════════════════════
log "2/8 System configuration..."

mount -t proc proc   "${ROOTFS}/proc"
mount -t sysfs sysfs "${ROOTFS}/sys"
mount --bind /dev    "${ROOTFS}/dev"

# Hostname
echo "secubox-live" > "${ROOTFS}/etc/hostname"
cat > "${ROOTFS}/etc/hosts" <<EOF
127.0.0.1  localhost secubox-live secubox
::1        localhost ip6-localhost ip6-loopback
EOF

# Root password: secubox
chroot "${ROOTFS}" bash -c 'echo "root:secubox" | chpasswd'

# Timezone
echo "Europe/Paris" > "${ROOTFS}/etc/timezone"
chroot "${ROOTFS}" dpkg-reconfigure -f noninteractive tzdata 2>/dev/null || true

# Locale
chroot "${ROOTFS}" bash -c "locale-gen en_US.UTF-8 fr_FR.UTF-8 || true"
echo 'LANG=fr_FR.UTF-8' > "${ROOTFS}/etc/default/locale"

# French keyboard
cat > "${ROOTFS}/etc/default/keyboard" <<EOF
XKBMODEL="pc105"
XKBLAYOUT="fr"
XKBVARIANT="latin9"
EOF
echo 'KEYMAP=fr' > "${ROOTFS}/etc/vconsole.conf"

# Enable SSH root login
sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' "${ROOTFS}/etc/ssh/sshd_config"

# ── Autologin root on tty1 ────────────────────────────────────────
mkdir -p "${ROOTFS}/etc/systemd/system/getty@tty1.service.d"
cat > "${ROOTFS}/etc/systemd/system/getty@tty1.service.d/override.conf" <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I \$TERM
Type=idle
EOF

# Disable live-config autologin
mkdir -p "${ROOTFS}/etc/live/config.conf.d"
echo 'LIVE_CONFIG_NOAUTOLOGIN=true' > "${ROOTFS}/etc/live/config.conf.d/no-autologin.conf"

# Quiet boot
mkdir -p "${ROOTFS}/etc/systemd/system.conf.d"
cat > "${ROOTFS}/etc/systemd/system.conf.d/quiet-boot.conf" <<EOF
[Manager]
ShowStatus=no
EOF

# Disable console spam
cat > "${ROOTFS}/etc/sysctl.d/99-secubox.conf" <<EOF
kernel.consoleblank=0
net.ipv4.conf.all.log_martians=0
kernel.printk=1 1 1 1
EOF

# ── Network config with dummy interface for kiosk ─────────────────
mkdir -p "${ROOTFS}/etc/netplan"

# Main netplan config - DHCP on all interfaces, optional so no boot block
cat > "${ROOTFS}/etc/netplan/00-secubox.yaml" <<'NETPLAN'
network:
  version: 2
  renderer: networkd
  ethernets:
    all-en:
      match:
        name: "en*"
      dhcp4: true
      optional: true
    all-eth:
      match:
        name: "eth*"
      dhcp4: true
      optional: true
NETPLAN
chmod 600 "${ROOTFS}/etc/netplan/00-secubox.yaml"

# Dummy interface with fixed IP - always available for kiosk/local access
cat > "${ROOTFS}/etc/systemd/network/10-dummy0.netdev" <<EOF
[NetDev]
Name=dummy0
Kind=dummy
EOF

cat > "${ROOTFS}/etc/systemd/network/10-dummy0.network" <<EOF
[Match]
Name=dummy0

[Network]
Address=192.168.255.1/24
EOF

# Fallback network script - runs after boot, adds link-local if no IP
cat > "${ROOTFS}/usr/sbin/secubox-net-fallback" <<'FALLBACK'
#!/bin/bash
# SecuBox Network Fallback - adds link-local IP if DHCP failed
sleep 10

for iface in /sys/class/net/en* /sys/class/net/eth*; do
    [ -e "$iface" ] || continue
    IFACE=$(basename "$iface")
    [ "$IFACE" = "lo" ] && continue

    # Check if interface has an IP
    if ! ip addr show "$IFACE" | grep -q "inet "; then
        echo "[net-fallback] No IP on $IFACE, adding fallback 169.254.1.1/16"
        ip addr add 169.254.1.1/16 dev "$IFACE" 2>/dev/null || true
        ip link set "$IFACE" up
    fi
done
FALLBACK
chmod +x "${ROOTFS}/usr/sbin/secubox-net-fallback"

# Systemd service for fallback
cat > "${ROOTFS}/etc/systemd/system/secubox-net-fallback.service" <<EOF
[Unit]
Description=SecuBox Network Fallback
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/secubox-net-fallback
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

chroot "${ROOTFS}" systemctl enable systemd-networkd.service 2>/dev/null || true
chroot "${ROOTFS}" systemctl enable secubox-net-fallback.service 2>/dev/null || true
chroot "${ROOTFS}" systemctl disable systemd-networkd-wait-online.service 2>/dev/null || true
chroot "${ROOTFS}" systemctl mask systemd-networkd-wait-online.service 2>/dev/null || true

ok "Base configuration complete"

# ══════════════════════════════════════════════════════════════════
# Step 3: Firmware
# ══════════════════════════════════════════════════════════════════
log "3/8 Installing firmware..."

cat > "${ROOTFS}/etc/apt/sources.list" <<EOF
deb ${APT_MIRROR} ${SUITE} main contrib non-free non-free-firmware
deb ${APT_MIRROR} ${SUITE}-updates main contrib non-free non-free-firmware
EOF

chroot "${ROOTFS}" apt-get update -q
chroot "${ROOTFS}" apt-get install -y -q --no-install-recommends \
  firmware-linux-free firmware-linux-nonfree firmware-misc-nonfree \
  firmware-realtek firmware-iwlwifi firmware-atheros \
  amd64-microcode intel-microcode 2>/dev/null || warn "Some firmware unavailable"

ok "Firmware installed"

# VM Guest support (VirtualBox, VMware, QEMU/KVM)
log "Installing VM guest support..."
chroot "${ROOTFS}" apt-get install -y -q --no-install-recommends \
  virtualbox-guest-utils \
  open-vm-tools \
  qemu-guest-agent \
  spice-vdagent \
  2>/dev/null || warn "Some VM guest packages unavailable"

ok "VM guest support installed"

# ══════════════════════════════════════════════════════════════════
# Step 4: SecuBox packages (slipstream ALL from cache/repo)
# ══════════════════════════════════════════════════════════════════
log "4/8 Installing ALL SecuBox packages..."

# Find all .deb files in cache/repo
CACHE_DEBS="${REPO_DIR}/cache/repo/pool"
if [[ -d "$CACHE_DEBS" ]] && find "$CACHE_DEBS" -name "*.deb" | head -1 | grep -q .; then
  log "Slipstream: Found packages in cache/repo/pool"
  install -d "${ROOTFS}/tmp/secubox-debs"

  # Copy ALL secubox debs
  find "$CACHE_DEBS" -name "secubox-*.deb" -exec cp {} "${ROOTFS}/tmp/secubox-debs/" \;
  DEB_COUNT=$(ls "${ROOTFS}/tmp/secubox-debs/"*.deb 2>/dev/null | wc -l)

  # List all packages to be installed
  log "Slipstream: ${DEB_COUNT} packages to install:"
  echo ""
  ls -1 "${ROOTFS}/tmp/secubox-debs/"*.deb | xargs -I{} basename {} | sed 's/_.*$//' | sort -u | while read pkg; do
    echo "  - ${pkg}"
  done
  echo ""

  # Install core first (dependency for all)
  if ls "${ROOTFS}/tmp/secubox-debs/secubox-core_"*.deb >/dev/null 2>&1; then
    log "Installing secubox-core (dependency)..."
    chroot "${ROOTFS}" dpkg -i /tmp/secubox-debs/secubox-core_*.deb 2>/dev/null || true
  fi

  # Install all packages
  log "Installing all packages..."
  chroot "${ROOTFS}" dpkg -i /tmp/secubox-debs/*.deb 2>/dev/null || true

  # Fix dependencies
  log "Fixing dependencies..."
  chroot "${ROOTFS}" apt-get install -f -y -q 2>/dev/null || true

  # Verify installations
  log "Verifying installations..."
  INSTALLED_COUNT=$(chroot "${ROOTFS}" dpkg -l 'secubox-*' 2>/dev/null | grep "^ii" | wc -l)

  # List installed packages
  echo ""
  log "Installed SecuBox packages (${INSTALLED_COUNT}):"
  chroot "${ROOTFS}" dpkg -l 'secubox-*' 2>/dev/null | grep "^ii" | awk '{print "  ✓ " $2 " (" $3 ")"}' || true
  echo ""

  # Save list to image
  chroot "${ROOTFS}" dpkg -l 'secubox-*' 2>/dev/null | grep "^ii" > "${ROOTFS}/var/lib/secubox/installed-packages.txt" || true

  rm -rf "${ROOTFS}/tmp/secubox-debs"
  ok "Slipstream: ${INSTALLED_COUNT}/${DEB_COUNT} packages installed successfully"
else
  warn "No packages in cache/repo, trying APT..."
  if curl -sf "${APT_SECUBOX}/dists/${SUITE}/Release" >/dev/null 2>&1; then
    cat > "${ROOTFS}/etc/apt/sources.list.d/secubox.list" <<EOF
deb [trusted=yes] ${APT_SECUBOX} ${SUITE} main
EOF
    chroot "${ROOTFS}" apt-get update -q
    chroot "${ROOTFS}" apt-get install -y -q secubox-full 2>/dev/null || warn "secubox-full unavailable"
  fi
fi

# Python deps
chroot "${ROOTFS}" pip3 install --break-system-packages -q \
  fastapi uvicorn python-jose httpx jinja2 tomli pyroute2 psutil 2>/dev/null || true

ok "SecuBox packages installed"

# ══════════════════════════════════════════════════════════════════
# Step 5: Network detection & kiosk scripts
# ══════════════════════════════════════════════════════════════════
log "5/8 Installing SecuBox scripts..."

mkdir -p "${ROOTFS}/usr/sbin"
mkdir -p "${ROOTFS}/usr/lib/secubox"

# Copy scripts
for script in secubox-net-detect secubox-kiosk-setup secubox-cmdline-handler; do
  if [[ -f "${SCRIPT_DIR}/sbin/${script}" ]]; then
    cp "${SCRIPT_DIR}/sbin/${script}" "${ROOTFS}/usr/sbin/"
    chmod +x "${ROOTFS}/usr/sbin/${script}"
  fi
done

# Copy firstboot
if [[ -f "${SCRIPT_DIR}/firstboot.sh" ]]; then
  cp "${SCRIPT_DIR}/firstboot.sh" "${ROOTFS}/usr/lib/secubox/"
  chmod +x "${ROOTFS}/usr/lib/secubox/firstboot.sh"
fi

# Systemd services
mkdir -p "${ROOTFS}/etc/systemd/system"
for svc in secubox-net-detect secubox-cmdline secubox-kiosk; do
  if [[ -f "${SCRIPT_DIR}/systemd/${svc}.service" ]]; then
    cp "${SCRIPT_DIR}/systemd/${svc}.service" "${ROOTFS}/etc/systemd/system/"
  fi
done

# Enable net-detect and cmdline services
chroot "${ROOTFS}" systemctl enable secubox-cmdline.service 2>/dev/null || true

# Firstboot service
cat > "${ROOTFS}/etc/systemd/system/secubox-firstboot.service" <<EOF
[Unit]
Description=SecuBox First Boot
After=network-online.target
ConditionPathExists=!/var/lib/secubox/.firstboot-done

[Service]
Type=oneshot
ExecStart=/usr/lib/secubox/firstboot.sh
ExecStartPost=/bin/touch /var/lib/secubox/.firstboot-done
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
chroot "${ROOTFS}" systemctl enable secubox-firstboot.service 2>/dev/null || true

# ── Kiosk mode packages ───────────────────────────────────────────
if [[ $INCLUDE_KIOSK -eq 1 ]]; then
  log "Installing kiosk mode packages..."
  chroot "${ROOTFS}" apt-get install -y -q --no-install-recommends \
    cage chromium fonts-dejavu-core \
    xwayland \
    libinput10 libegl1 libgles2 libgbm1 libdrm2 \
    mesa-utils xdg-utils 2>/dev/null || warn "Kiosk packages failed"

  # Create kiosk user with UID 1000
  if ! chroot "${ROOTFS}" id secubox-kiosk &>/dev/null; then
    chroot "${ROOTFS}" useradd -r -u 1000 -m -d /home/secubox-kiosk -s /usr/sbin/nologin \
      -G video,audio,input,render secubox-kiosk 2>/dev/null || \
    chroot "${ROOTFS}" useradd -r -m -d /home/secubox-kiosk -s /usr/sbin/nologin \
      -G video,audio,input,render secubox-kiosk
    ok "Created kiosk user"
  fi

  # Create kiosk start script
  mkdir -p "${ROOTFS}/home/secubox-kiosk/.config"
  cat > "${ROOTFS}/home/secubox-kiosk/start-kiosk.sh" <<'KIOSK_SCRIPT'
#!/bin/bash
# SecuBox Kiosk Launcher

# Wait for services to be ready
for i in {1..30}; do
    if curl -sk https://192.168.255.1:9443/ >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Kiosk URL (local SecuBox WebUI via dummy interface or localhost)
URL="${KIOSK_URL:-https://192.168.255.1:9443/}"

# Chromium flags for kiosk mode (native Wayland via Ozone)
CHROMIUM_FLAGS=(
    --ozone-platform=wayland
    --kiosk
    --no-first-run
    --disable-translate
    --disable-infobars
    --disable-session-crashed-bubble
    --disable-restore-background-contents
    --disable-sync
    --disable-features=TranslateUI
    --ignore-certificate-errors
    --noerrdialogs
    --enable-features=OverlayScrollbar
    --start-fullscreen
    --window-position=0,0
    --check-for-update-interval=604800
    --disable-component-update
    --disable-default-apps
    --disable-extensions
    --disable-background-networking
    --disable-domain-reliability
    --disable-client-side-phishing-detection
    "$URL"
)

exec chromium "${CHROMIUM_FLAGS[@]}"
KIOSK_SCRIPT
  chmod +x "${ROOTFS}/home/secubox-kiosk/start-kiosk.sh"
  chroot "${ROOTFS}" chown -R secubox-kiosk:secubox-kiosk /home/secubox-kiosk

  # Mark as installed AND enabled (so kiosk starts on first boot)
  mkdir -p "${ROOTFS}/var/lib/secubox"
  echo "installed=$(date -Iseconds)" > "${ROOTFS}/var/lib/secubox/.kiosk-installed"
  touch "${ROOTFS}/var/lib/secubox/.kiosk-enabled"

  # Enable kiosk service and set graphical target
  chroot "${ROOTFS}" systemctl enable secubox-kiosk.service 2>/dev/null || true
  chroot "${ROOTFS}" systemctl set-default graphical.target 2>/dev/null || true
  chroot "${ROOTFS}" systemctl disable getty@tty1.service 2>/dev/null || true

  # Setup root autologin on tty2 (console access while kiosk runs on tty1)
  mkdir -p "${ROOTFS}/etc/systemd/system/getty@tty2.service.d"
  cat > "${ROOTFS}/etc/systemd/system/getty@tty2.service.d/autologin.conf" <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I \$TERM
Type=idle
EOF
  chroot "${ROOTFS}" systemctl enable getty@tty2.service 2>/dev/null || true

  ok "Kiosk packages and user installed (console on tty2)"
fi

ok "Scripts installed"

# ══════════════════════════════════════════════════════════════════
# Step 6: Cleanup rootfs
# ══════════════════════════════════════════════════════════════════
log "6/8 Cleaning up rootfs..."

# Preseed
if [[ -n "$PRESEED_FILE" ]] && [[ -f "$PRESEED_FILE" ]]; then
  mkdir -p "${ROOTFS}/usr/share/secubox"
  cp "$PRESEED_FILE" "${ROOTFS}/usr/share/secubox/preseed.tar.gz"
  ok "Preseed included"
fi

# Mask problematic services
for svc in lxc-net lxc; do
  chroot "${ROOTFS}" systemctl disable ${svc}.service 2>/dev/null || true
  chroot "${ROOTFS}" systemctl mask ${svc}.service 2>/dev/null || true
done

# Ensure required modules for live-boot are in initramfs
log "Configuring initramfs modules..."
cat >> "${ROOTFS}/etc/initramfs-tools/modules" <<EOF
# Live boot requirements
loop
squashfs
overlay
isofs
EOF

# Configure live-boot
mkdir -p "${ROOTFS}/etc/live/boot.conf.d"
cat > "${ROOTFS}/etc/live/boot.conf.d/secubox.conf" <<EOF
# SecuBox Live configuration
LIVE_MEDIA_PATH=/live
EOF

# Ensure initramfs includes live-boot scripts
echo "RESUME=none" > "${ROOTFS}/etc/initramfs-tools/conf.d/resume"

# Regenerate initramfs with live-boot hooks
log "Regenerating initramfs with live-boot support..."
chroot "${ROOTFS}" update-initramfs -u -k all

# Clean APT
chroot "${ROOTFS}" apt-get clean
rm -rf "${ROOTFS}/var/lib/apt/lists"/*
rm -rf "${ROOTFS}/var/cache/apt"/*.bin
rm -rf "${ROOTFS}/tmp"/*

# Welcome message
cat > "${ROOTFS}/etc/motd" <<'EOF'

  ╔═══════════════════════════════════════════════════════════════╗
  ║   ███████╗███████╗ ██████╗██╗   ██╗██████╗  ██████╗ ██╗  ██╗  ║
  ║   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔═══██╗╚██╗██╔╝  ║
  ║   ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║ ╚███╔╝   ║
  ║   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║ ██╔██╗   ║
  ║   ███████║███████╗╚██████╗╚██████╔╝██████╔╝╚██████╔╝██╔╝ ██╗  ║
  ║   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝  ║
  ║                       LIVE USB                                ║
  ╚═══════════════════════════════════════════════════════════════╝

  Web UI:  https://<IP>:9443    SSH: root / secubox

EOF

# Unmount
umount -lf "${ROOTFS}/proc" 2>/dev/null || true
umount -lf "${ROOTFS}/sys"  2>/dev/null || true
umount -lf "${ROOTFS}/dev"  2>/dev/null || true

ok "Rootfs cleaned"

# ══════════════════════════════════════════════════════════════════
# Step 7: Create SquashFS
# ══════════════════════════════════════════════════════════════════
log "7/8 Creating SquashFS filesystem..."
mkdir -p "${LIVE_DIR}/live"

mksquashfs "${ROOTFS}" "${LIVE_DIR}/live/filesystem.squashfs" \
  -comp xz -b 1M -Xdict-size 100% -e boot/grub -e boot/efi

cp "${ROOTFS}/boot/vmlinuz-"* "${LIVE_DIR}/live/vmlinuz"
cp "${ROOTFS}/boot/initrd.img-"* "${LIVE_DIR}/live/initrd.img"

SQUASHFS_SIZE=$(du -sh "${LIVE_DIR}/live/filesystem.squashfs" | cut -f1)
ok "SquashFS: ${SQUASHFS_SIZE}"

# ══════════════════════════════════════════════════════════════════
# Step 8: Create bootable image
# ══════════════════════════════════════════════════════════════════
log "8/8 Creating bootable image (${IMG_SIZE})..."

# Delete old image
rm -f "${IMG_FILE}" "${IMG_FILE}.gz"

# Create image
truncate -s "${IMG_SIZE}" "${IMG_FILE}"

# Partition: GPT with hybrid boot
# 1: BIOS boot (2MB) - legacy grub
# 2: ESP (512MB) - UEFI
# 3: LIVE (4GB) - squashfs
# 4: persistence (rest) - optional
if [[ $INCLUDE_PERSISTENCE -eq 1 ]]; then
  parted -s "${IMG_FILE}" \
    mklabel gpt \
    mkpart bios 1MiB 3MiB \
    mkpart ESP fat32 3MiB 515MiB \
    mkpart LIVE ext4 515MiB 4611MiB \
    mkpart persistence ext4 4611MiB 100% \
    set 1 bios_grub on \
    set 2 esp on \
    set 2 boot on
else
  parted -s "${IMG_FILE}" \
    mklabel gpt \
    mkpart bios 1MiB 3MiB \
    mkpart ESP fat32 3MiB 515MiB \
    mkpart LIVE ext4 515MiB 100% \
    set 1 bios_grub on \
    set 2 esp on \
    set 2 boot on
fi

# Setup loop
LOOP=$(losetup -f --show -P "${IMG_FILE}")
log "Loop: ${LOOP}"

# Wait for partitions
sleep 1
partprobe "${LOOP}" 2>/dev/null || true
sleep 1

# Verify partitions exist
[[ -b "${LOOP}p2" ]] || err "Partition ${LOOP}p2 not found"

# Format
mkfs.fat -F32 -n ESP "${LOOP}p2"
mkfs.ext4 -L LIVE -q "${LOOP}p3"
if [[ $INCLUDE_PERSISTENCE -eq 1 ]] && [[ -b "${LOOP}p4" ]]; then
  mkfs.ext4 -L persistence -q "${LOOP}p4"
fi

# Mount
MNT="${WORK_DIR}/mnt"
mkdir -p "${MNT}/esp" "${MNT}/live"
mount "${LOOP}p2" "${MNT}/esp"
mount "${LOOP}p3" "${MNT}/live"

# Copy live files
mkdir -p "${MNT}/live/live"
cp "${LIVE_DIR}/live/filesystem.squashfs" "${MNT}/live/live/"
cp "${LIVE_DIR}/live/vmlinuz" "${MNT}/live/live/"
cp "${LIVE_DIR}/live/initrd.img" "${MNT}/live/live/"

# Setup ESP
mkdir -p "${MNT}/esp/EFI/BOOT"
mkdir -p "${MNT}/esp/boot/grub/x86_64-efi"
mkdir -p "${MNT}/esp/boot/grub/i386-pc"

# Also copy to ESP for some UEFI
mkdir -p "${MNT}/esp/live"
cp "${LIVE_DIR}/live/vmlinuz" "${MNT}/esp/live/"
cp "${LIVE_DIR}/live/initrd.img" "${MNT}/esp/live/"

# GRUB config
cat > "${MNT}/esp/boot/grub/grub.cfg" <<'GRUBCFG'
set default=0
set timeout=5

insmod part_gpt
insmod fat
insmod ext2
insmod all_video

search --no-floppy --label LIVE --set=live

set menu_color_normal=cyan/black
set menu_color_highlight=white/blue

menuentry "SecuBox Live" {
    linux ($live)/live/vmlinuz boot=live components persistence quiet
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Kiosk GUI)" {
    linux ($live)/live/vmlinuz boot=live components persistence quiet secubox.kiosk=1 systemd.unit=graphical.target
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Bridge Mode)" {
    linux ($live)/live/vmlinuz boot=live components persistence quiet secubox.netmode=bridge
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Safe Mode)" {
    linux ($live)/live/vmlinuz boot=live components nomodeset nosplash
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (To RAM)" {
    linux ($live)/live/vmlinuz boot=live components toram
    initrd ($live)/live/initrd.img
}
GRUBCFG

cp "${MNT}/esp/boot/grub/grub.cfg" "${MNT}/esp/EFI/BOOT/grub.cfg"

# Build GRUB EFI
GRUB_MODS="part_gpt part_msdos fat ext2 normal linux boot configfile loopback chain efi_gop efi_uga ls search search_label gfxterm all_video"

cat > "${WORK_DIR}/grub-embed.cfg" <<'EMBEDCFG'
search --no-floppy --label ESP --set=root
set prefix=($root)/boot/grub
configfile $prefix/grub.cfg
EMBEDCFG

grub-mkimage -o "${MNT}/esp/EFI/BOOT/BOOTX64.EFI" \
  -O x86_64-efi \
  -c "${WORK_DIR}/grub-embed.cfg" \
  -p /boot/grub \
  ${GRUB_MODS}

cp "${MNT}/esp/EFI/BOOT/BOOTX64.EFI" "${MNT}/esp/EFI/BOOT/grubx64.efi"

# Copy GRUB modules
cp /usr/lib/grub/x86_64-efi/*.mod "${MNT}/esp/boot/grub/x86_64-efi/" 2>/dev/null || true

# Install BIOS GRUB
grub-install --target=i386-pc --boot-directory="${MNT}/esp/boot" --recheck "${LOOP}" 2>/dev/null || warn "BIOS GRUB failed"
cp /usr/lib/grub/i386-pc/*.mod "${MNT}/esp/boot/grub/i386-pc/" 2>/dev/null || true

ok "GRUB installed (UEFI + BIOS)"

# Persistence
if [[ $INCLUDE_PERSISTENCE -eq 1 ]] && [[ -b "${LOOP}p4" ]]; then
  mkdir -p "${MNT}/pers"
  mount "${LOOP}p4" "${MNT}/pers"
  echo "/ union" > "${MNT}/pers/persistence.conf"
  umount "${MNT}/pers"
  ok "Persistence configured"
fi

# Sync and unmount
sync
umount "${MNT}/esp"
umount "${MNT}/live"
losetup -d "${LOOP}"
LOOP=""

ok "Bootable image created"

# ══════════════════════════════════════════════════════════════════
# Compress (optional)
# ══════════════════════════════════════════════════════════════════
if [[ $NO_COMPRESS -eq 0 ]]; then
  log "Compressing..."
  gzip -9 -f "${IMG_FILE}"
  sha256sum "${IMG_FILE}.gz" > "${IMG_FILE}.gz.sha256"
  FINAL_SIZE=$(du -sh "${IMG_FILE}.gz" | cut -f1)
  FINAL_IMG="${IMG_FILE}.gz"
  FLASH_CMD="zcat ${IMG_FILE}.gz | sudo dd of=/dev/sdX bs=4M status=progress"
else
  log "Skipping compression (--no-compress)"
  sha256sum "${IMG_FILE}" > "${IMG_FILE}.sha256"
  FINAL_SIZE=$(du -sh "${IMG_FILE}" | cut -f1)
  FINAL_IMG="${IMG_FILE}"
  FLASH_CMD="sudo dd if=${IMG_FILE} of=/dev/sdX bs=4M status=progress"
fi

echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  SecuBox Live USB Ready!${NC}"
echo ""
echo -e "  Image: ${FINAL_IMG}"
echo -e "  Size:  ${FINAL_SIZE}"
echo ""
echo -e "  ${BOLD}Flash:${NC}"
echo -e "    ${FLASH_CMD}"
echo ""
echo -e "  ${BOLD}Credentials:${NC}"
echo -e "    SSH/Console: root / secubox"
echo -e "    Web UI: https://192.168.255.1:9443"
echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════${NC}"
