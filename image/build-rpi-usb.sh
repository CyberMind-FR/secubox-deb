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
SLIPSTREAM_DEBS=0

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
  --slipstream       Install .deb packages from output/debs/
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
    --slipstream)   SLIPSTREAM_DEBS=1;  shift   ;;
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

cleanup() {
  log "Cleaning up..."
  # Unmount in reverse order
  umount "${MNT:-}/boot/firmware" 2>/dev/null || true
  umount "${MNT:-}" 2>/dev/null || true
  umount -R "${ROOTFS}" 2>/dev/null || true
  # Release loop device
  if [[ -n "${LOOP:-}" ]]; then
    losetup -d "$LOOP" 2>/dev/null || true
  fi
  # Clean workdir
  rm -rf "${WORK_DIR}" 2>/dev/null || true
}
trap "cleanup" EXIT

mkdir -p "${OUT_DIR}" "${ROOTFS}"

log "══════════════════════════════════════════════════════════"
log "SecuBox Raspberry Pi 400 Image Builder"
log "Suite: ${SUITE} | Size: ${IMG_SIZE}"
log "══════════════════════════════════════════════════════════"

# ══════════════════════════════════════════════════════════════════
# Step 1: Debootstrap ARM64
# ══════════════════════════════════════════════════════════════════
log "1/7 Debootstrap arm64..."

# IMPORTANT: Do NOT include kernel/initramfs in debootstrap!
# initramfs generation under QEMU takes 30+ minutes
# We install kernel AFTER debootstrap with initramfs disabled
INCLUDE_PKGS="systemd,systemd-sysv,dbus,nftables,openssh-server"
INCLUDE_PKGS+=",python3,python3-pip,nginx,curl,wget,ca-certificates,gnupg"
INCLUDE_PKGS+=",iproute2,iputils-ping,net-tools,wireguard-tools"
INCLUDE_PKGS+=",sudo,less,vim-tiny,cron,rsync,jq"
INCLUDE_PKGS+=",parted,dosfstools,e2fsprogs,pciutils,usbutils"
# Note: linux-image-arm64, plymouth, initramfs-tools installed later

debootstrap --arch=arm64 --foreign --include="${INCLUDE_PKGS}" \
  "${SUITE}" "${ROOTFS}" "${APT_MIRROR}"

# Complete second stage with QEMU
cp /usr/bin/qemu-aarch64-static "${ROOTFS}/usr/bin/"
log "Running debootstrap second stage (this may take a few minutes)..."
chroot "${ROOTFS}" /debootstrap/debootstrap --second-stage

ok "Debootstrap complete"

# ══════════════════════════════════════════════════════════════════
# Step 2: Base configuration
# ══════════════════════════════════════════════════════════════════
log "2/7 System configuration..."

# Hostname
echo "secubox-rpi" > "${ROOTFS}/etc/hostname"
cat > "${ROOTFS}/etc/hosts" <<EOF
127.0.0.1   localhost secubox.local
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

# ── Boot Menu System ──────���──────────────────────────────────────────
log "Installing boot menu system..."

# Boot menu script - shows on early boot with timeout
cat > "${ROOTFS}/usr/local/bin/secubox-bootmenu" <<'BOOTMENU'
#!/bin/bash
# SecuBox Boot Menu - Raspberry Pi Edition
# Runs early in boot to select operating mode

ESC="\033"
CYAN="${ESC}[36m"
GREEN="${ESC}[32m"
GOLD="${ESC}[33m"
WHITE="${ESC}[97m"
DIM="${ESC}[2m"
BOLD="${ESC}[1m"
RESET="${ESC}[0m"
CLEAR="${ESC}[2J${ESC}[H"

MODE_FILE="/var/lib/secubox/boot-mode"
DEFAULT_MODE="normal"
TIMEOUT=5

# Load saved mode
[[ -f "$MODE_FILE" ]] && DEFAULT_MODE=$(cat "$MODE_FILE")

show_menu() {
    echo -ne "$CLEAR"
    echo -e "${CYAN}${BOLD}"
    cat << 'LOGO'
   _____ ______ _____ _    _ ____   ______   __
  / ____|  ____/ ____| |  | |  _ \ / __ \ \ / /
 | (___ | |__ | |    | |  | | |_) | |  | \ V /
  \___ \|  __|| |    | |  | |  _ <| |  | |> <
  ____) | |___| |____| |__| | |_) | |__| / . \
 |_____/|______\_____|\____/|____/ \____/_/ \_\
LOGO
    echo -e "${RESET}"
    echo -e "${WHITE}${BOLD}  RASPBERRY PI 400 - BOOT MODE SELECTION${RESET}"
    echo -e "${DIM}  ───��─────────────────────────────────────${RESET}"
    echo ""
    echo -e "  ${GREEN}1)${RESET} ${BOLD}Normal${RESET}      - Standard SecuBox with SSH + Web UI"
    echo -e "  ${GREEN}2)${RESET} ${BOLD}Kiosk${RESET}       - Fullscreen browser dashboard"
    echo -e "  ${GREEN}3)${RESET} ${BOLD}Console${RESET}     - Text-based TUI dashboard"
    echo -e "  ${GREEN}4)${RESET} ${BOLD}Bridge${RESET}      - Transparent inline bridge mode"
    echo -e "  ${GREEN}5)${RESET} ${BOLD}Minimal${RESET}     - SSH only, no services"
    echo ""
    echo -e "${DIM}  ──���───────────────────────────��──────────${RESET}"
    echo -e "  ${GOLD}Current: ${WHITE}${DEFAULT_MODE}${RESET}"
    echo ""
}

apply_mode() {
    local mode="$1"
    mkdir -p /var/lib/secubox
    echo "$mode" > "$MODE_FILE"

    case "$mode" in
        normal)
            systemctl set-default multi-user.target
            systemctl disable secubox-kiosk.service 2>/dev/null || true
            ;;
        kiosk)
            systemctl set-default graphical.target
            systemctl enable secubox-kiosk.service 2>/dev/null || true
            ;;
        console)
            systemctl set-default multi-user.target
            systemctl enable secubox-console.service 2>/dev/null || true
            ;;
        bridge)
            systemctl set-default multi-user.target
            systemctl enable secubox-bridge.service 2>/dev/null || true
            ;;
        minimal)
            systemctl set-default multi-user.target
            systemctl disable nginx secubox-hub secubox-portal 2>/dev/null || true
            ;;
    esac
}

# Check if we should show menu (hold SHIFT or first boot)
SHOW_MENU=0
if [[ ! -f "$MODE_FILE" ]]; then
    SHOW_MENU=1  # First boot
elif [[ -f /tmp/secubox-show-menu ]]; then
    SHOW_MENU=1
    rm -f /tmp/secubox-show-menu
fi

# Check for key press (simplified - check if SHIFT held)
read -t 0.1 -n 1 key 2>/dev/null && SHOW_MENU=1

if [[ $SHOW_MENU -eq 1 ]]; then
    show_menu
    echo -ne "  ${WHITE}Select mode [1-5] or ENTER for default (${TIMEOUT}s): ${RESET}"

    read -t $TIMEOUT -n 1 choice
    echo ""

    case "$choice" in
        1) apply_mode "normal" ;;
        2) apply_mode "kiosk" ;;
        3) apply_mode "console" ;;
        4) apply_mode "bridge" ;;
        5) apply_mode "minimal" ;;
        *) apply_mode "$DEFAULT_MODE" ;;
    esac

    echo -e "  ${GREEN}Mode set: $(cat $MODE_FILE)${RESET}"
    sleep 1
else
    # Silent apply current mode
    apply_mode "$DEFAULT_MODE"
fi
BOOTMENU
chmod +x "${ROOTFS}/usr/local/bin/secubox-bootmenu"

# Systemd service to run boot menu early
cat > "${ROOTFS}/etc/systemd/system/secubox-bootmenu.service" <<'BOOTSVC'
[Unit]
Description=SecuBox Boot Mode Selector
DefaultDependencies=no
Before=sysinit.target
After=systemd-vconsole-setup.service
ConditionPathExists=!/run/secubox/bootmenu-done

[Service]
Type=oneshot
ExecStart=/usr/local/bin/secubox-bootmenu
ExecStartPost=/usr/bin/touch /run/secubox/bootmenu-done
StandardInput=tty
StandardOutput=tty
TTYPath=/dev/tty1
TTYReset=yes
TTYVHangup=yes

[Install]
WantedBy=sysinit.target
BOOTSVC

chroot "${ROOTFS}" systemctl enable secubox-bootmenu.service 2>/dev/null || true

# Script to trigger boot menu on next reboot
cat > "${ROOTFS}/usr/local/bin/secubox-bootmenu-show" <<'SHOWMENU'
#!/bin/bash
touch /tmp/secubox-show-menu
echo "Boot menu will be shown on next reboot."
echo "Use 'reboot' to restart now."
SHOWMENU
chmod +x "${ROOTFS}/usr/local/bin/secubox-bootmenu-show"

ok "Boot menu system installed"

# Add splash to root's bashrc
cat >> "${ROOTFS}/root/.bashrc" <<'BASHRC'

# SecuBox Cyber Splash on login
if [ -t 0 ] && [ -z "$SECUBOX_SPLASH_SHOWN" ]; then
    export SECUBOX_SPLASH_SHOWN=1
    /usr/local/bin/secubox-splash 2>/dev/null || true
fi
BASHRC

# ── Plymouth Boot Splash Theme (SecuBox Cube) ──────────────────────
log "Installing Plymouth SecuBox-Cube boot splash..."

PLYMOUTH_DIR="${ROOTFS}/usr/share/plymouth/themes/secubox-cube"
mkdir -p "${PLYMOUTH_DIR}"

# Copy theme assets from source
CUBE_SRC="${SCRIPT_DIR}/plymouth/secubox-cube"
if [[ -d "${CUBE_SRC}" ]]; then
    cp "${CUBE_SRC}/secubox-cube.plymouth" "${PLYMOUTH_DIR}/"
    cp "${CUBE_SRC}/secubox-cube.script" "${PLYMOUTH_DIR}/"
    cp "${CUBE_SRC}/logo.png" "${PLYMOUTH_DIR}/"
    cp "${CUBE_SRC}/scanlines.png" "${PLYMOUTH_DIR}/"
    cp "${CUBE_SRC}/progress-bg.png" "${PLYMOUTH_DIR}/"
    cp "${CUBE_SRC}/progress-fg.png" "${PLYMOUTH_DIR}/"
    cp "${CUBE_SRC}"/icon-*.png "${PLYMOUTH_DIR}/"
    log "  Copied cube theme assets from ${CUBE_SRC}"
else
    warn "Cube theme source not found, creating minimal theme..."
    cat > "${PLYMOUTH_DIR}/secubox-cube.plymouth" <<'PLYTHEME'
[Plymouth Theme]
Name=SecuBox Cube
Description=SecuBox 3D Rotating Cube Boot Splash
ModuleName=script

[script]
ImageDir=/usr/share/plymouth/themes/secubox-cube
ScriptFile=/usr/share/plymouth/themes/secubox-cube/secubox-cube.script
PLYTHEME

    cat > "${PLYMOUTH_DIR}/secubox-cube.script" <<'PLYSCRIPT'
Window.SetBackgroundTopColor(0.0, 0.0, 0.0);
Window.SetBackgroundBottomColor(0.02, 0.04, 0.02);
screen_width = Window.GetWidth();
screen_height = Window.GetHeight();
center_x = screen_width / 2;
center_y = screen_height / 2;
banner_image = Image.Text("SECUBOX", 0.0, 1.0, 0.61, "Sans Bold 48");
banner_sprite = Sprite(banner_image);
banner_sprite.SetPosition(center_x - banner_image.GetWidth() / 2, center_y - 50, 1);
fun boot_progress_callback(duration, progress) {
    bar_text = "";
    for (i = 0; i < Math.Int(progress * 30); i++) bar_text = bar_text + "█";
    for (i = Math.Int(progress * 30); i < 30; i++) bar_text = bar_text + "░";
    bar_image = Image.Text(bar_text, 0.0, 0.8, 0.4, "Mono 12");
    bar_sprite = Sprite(bar_image);
    bar_sprite.SetPosition(center_x - bar_image.GetWidth() / 2, center_y + 80, 1);
}
Plymouth.SetBootProgressFunction(boot_progress_callback);
PLYSCRIPT
fi

mkdir -p "${ROOTFS}/etc/plymouth"
cat > "${ROOTFS}/etc/plymouth/plymouthd.conf" <<EOF
[Daemon]
Theme=secubox-cube
ShowDelay=0
DeviceTimeout=8
EOF

chroot "${ROOTFS}" plymouth-set-default-theme secubox-cube 2>/dev/null || true

mkdir -p "${ROOTFS}/etc/initramfs-tools/conf.d"
echo "FRAMEBUFFER=y" > "${ROOTFS}/etc/initramfs-tools/conf.d/plymouth"

ok "Plymouth SecuBox-Cube theme installed"

ok "System configured"

# ══════════════════════════════════════════════════════════════════
# Step 3: Network configuration
# ══════════════════════════════════════════════════════════════════
log "3/7 Network configuration..."

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
# Step 4: Kernel and firmware (BEFORE SecuBox packages to keep apt clean)
# ══════════════════════════════════════════════════════════════════
log "4/7 Installing kernel and firmware..."

# APT sources
cat > "${ROOTFS}/etc/apt/sources.list" <<EOF
deb ${APT_MIRROR} ${SUITE} main contrib non-free non-free-firmware
deb ${APT_MIRROR} ${SUITE}-updates main contrib non-free non-free-firmware
EOF

chroot "${ROOTFS}" apt-get update -q

# Disable initramfs generation during package install (QEMU is too slow)
# We'll generate it manually later
mkdir -p "${ROOTFS}/etc/initramfs-tools"
cat > "${ROOTFS}/etc/initramfs-tools/update-initramfs.conf" <<EOF
# Disabled during image build (QEMU too slow)
# Re-enable on first boot if needed
update_initramfs=no
EOF

# Create hook to skip initramfs during kernel install
mkdir -p "${ROOTFS}/etc/kernel/postinst.d"
cat > "${ROOTFS}/etc/kernel/postinst.d/zz-skip-initramfs" <<'HOOK'
#!/bin/sh
# Skip initramfs during image build
if [ -f /etc/initramfs-tools/update-initramfs.conf ]; then
    grep -q "update_initramfs=no" /etc/initramfs-tools/update-initramfs.conf && exit 0
fi
HOOK
chmod +x "${ROOTFS}/etc/kernel/postinst.d/zz-skip-initramfs"

# Install kernel, initramfs-tools, firmware, and Python deps while apt is clean
log "Installing kernel and base packages..."
chroot "${ROOTFS}" apt-get install -y -q --no-install-recommends \
  linux-image-arm64 initramfs-tools plymouth plymouth-themes \
  raspi-firmware firmware-brcm80211 firmware-misc-nonfree \
  python3-pip python3-venv python3-netifaces \
  2>/dev/null || warn "Some packages may have failed (continuing)"

# Remove the skip hook now
rm -f "${ROOTFS}/etc/kernel/postinst.d/zz-skip-initramfs"

# Re-enable initramfs updates
cat > "${ROOTFS}/etc/initramfs-tools/update-initramfs.conf" <<EOF
update_initramfs=yes
EOF

# Check kernel was installed
if ls "${ROOTFS}/lib/modules/"* >/dev/null 2>&1; then
  ok "Kernel and firmware installed"
else
  warn "Kernel may not have installed properly"
fi

# Install Python dependencies via pip
log "Installing Python dependencies via pip..."
chroot "${ROOTFS}" pip3 install --break-system-packages -q \
  fastapi uvicorn[standard] python-jose[cryptography] httpx \
  jinja2 tomli toml pyroute2 psutil pydantic \
  aiofiles aiosqlite authlib cryptography \
  python-multipart websockets netifaces \
  2>&1 | tail -10 || true
ok "Python dependencies installed"

# ══════════════════════════════════════════════════════════════════
# Step 5: SecuBox packages
# ══════════════════════════════════════════════════════════════════
log "5/7 Installing SecuBox packages..."

# Pre-generate SSL certificates for nginx (BEFORE package install)
# Packages' postinst scripts check for nginx/certs, so create them first
log "Pre-generating SSL certificates..."
mkdir -p "${ROOTFS}/etc/secubox/tls"
mkdir -p "${ROOTFS}/run/secubox"
mkdir -p "${ROOTFS}/var/lib/secubox"
mkdir -p "${ROOTFS}/etc/nginx/secubox.d"

# Generate on host system (chroot may lack /dev/urandom)
openssl req -x509 -newkey rsa:2048 -days 365 \
  -keyout "${ROOTFS}/etc/secubox/tls/key.pem" \
  -out "${ROOTFS}/etc/secubox/tls/cert.pem" \
  -nodes -subj "/CN=secubox-rpi/O=CyberMind SecuBox/C=FR" \
  -addext "subjectAltName=DNS:localhost,DNS:secubox.local,IP:127.0.0.1,IP:192.168.1.1" \
  2>/dev/null

if [[ -f "${ROOTFS}/etc/secubox/tls/cert.pem" ]]; then
  chmod 640 "${ROOTFS}/etc/secubox/tls/key.pem"
  chmod 644 "${ROOTFS}/etc/secubox/tls/cert.pem"
  ok "SSL certificates pre-generated"
else
  warn "SSL cert generation failed"
fi

# SecuBox packages installation
install -d "${ROOTFS}/tmp/secubox-debs"
DEBS_INSTALLED=0

# Method 1: Slipstream from output/debs/ (--slipstream flag)
if [[ $SLIPSTREAM_DEBS -eq 1 ]]; then
  DEBS_DIR="${REPO_DIR}/output/debs"
  if [[ -d "${DEBS_DIR}" ]] && ls "${DEBS_DIR}"/secubox-*.deb >/dev/null 2>&1; then
    log "Slipstream: installing packages from output/debs/..."
    cp "${DEBS_DIR}"/secubox-*_all.deb "${ROOTFS}/tmp/secubox-debs/" 2>/dev/null || true
    cp "${DEBS_DIR}"/secubox-*_arm64.deb "${ROOTFS}/tmp/secubox-debs/" 2>/dev/null || true
    DEBS_INSTALLED=1
  else
    warn "Slipstream: no .deb files found in ${DEBS_DIR}"
  fi
fi

# Method 2: Fallback to local cache
if [[ $DEBS_INSTALLED -eq 0 ]]; then
  CACHE_DEBS="${REPO_DIR}/cache/repo/pool"
  if [[ -d "$CACHE_DEBS" ]]; then
    log "Installing SecuBox packages from cache..."
    find "$CACHE_DEBS" -name "secubox-*_all.deb" -exec cp {} "${ROOTFS}/tmp/secubox-debs/" \;
    find "$CACHE_DEBS" -name "secubox-*_arm64.deb" -exec cp {} "${ROOTFS}/tmp/secubox-debs/" \; 2>/dev/null || true
    DEBS_INSTALLED=1
  fi
fi

# Install collected packages
DEB_COUNT=$(ls "${ROOTFS}/tmp/secubox-debs/"*.deb 2>/dev/null | wc -l)
if [[ $DEB_COUNT -gt 0 ]]; then
  log "Installing ${DEB_COUNT} SecuBox packages..."

  # Ensure systemd directories exist before dpkg
  install -d -m 755 "${ROOTFS}/usr/lib/systemd/system"
  install -d -m 755 "${ROOTFS}/etc/systemd/system"

  # Install secubox-core first (dependency)
  if ls "${ROOTFS}/tmp/secubox-debs/secubox-core_"*.deb >/dev/null 2>&1; then
    chroot "${ROOTFS}" bash -c 'dpkg -i --force-depends /tmp/secubox-debs/secubox-core_*.deb' 2>/dev/null || true
  fi

  # Install all packages with force-depends (pip provides Python deps)
  # Note: Don't use head with pipefail - causes SIGPIPE failure
  chroot "${ROOTFS}" bash -c 'dpkg -i --force-depends --force-overwrite /tmp/secubox-debs/*.deb' 2>&1 | \
    grep -v "^dpkg: warning" || true

  # Configure packages (skip apt-get -f as pip provides Python deps)
  chroot "${ROOTFS}" dpkg --configure -a --force-confold 2>/dev/null || true

  # Count installed
  INSTALLED=$(chroot "${ROOTFS}" dpkg -l 'secubox-*' 2>/dev/null | grep "^ii" | wc -l)
  ok "Installed ${INSTALLED}/${DEB_COUNT} SecuBox packages"
else
  warn "No SecuBox packages found to install"
fi

rm -rf "${ROOTFS}/tmp/secubox-debs"

# ── Nginx cleanup after package install ──────────────────────────────────
log "Cleaning bad nginx configs from conf.d..."
for conf in "${ROOTFS}/etc/nginx/conf.d/"*secubox*.conf "${ROOTFS}/etc/nginx/conf.d/secubox-"*; do
  [[ -f "$conf" ]] || [[ -L "$conf" ]] || continue
  real_file="$conf"
  if [[ -L "$conf" ]]; then
    target=$(readlink "$conf")
    if [[ "$target" == /* ]]; then
      real_file="${ROOTFS}${target}"
    else
      real_file="${ROOTFS}/etc/nginx/conf.d/${target}"
    fi
  fi
  if [[ -f "$real_file" ]] && grep -q "^location" "$real_file" 2>/dev/null; then
    base=$(basename "$conf" .conf | sed 's/^secubox-//')
    mkdir -p "${ROOTFS}/etc/nginx/secubox.d"
    if [[ ! -f "${ROOTFS}/etc/nginx/secubox.d/${base}.conf" ]]; then
      cp "$real_file" "${ROOTFS}/etc/nginx/secubox.d/${base}.conf" 2>/dev/null || true
    fi
    rm -f "$conf"
  fi
done

log "Cleaning bad nginx configs from sites-enabled..."
for site in "${ROOTFS}/etc/nginx/sites-enabled/"*; do
  [[ -f "$site" ]] || [[ -L "$site" ]] || continue
  [[ "$(basename "$site")" == "secubox" ]] && continue
  real_file="$site"
  [[ -L "$site" ]] && real_file=$(readlink -f "$site") && real_file="${ROOTFS}${real_file#${ROOTFS}}"
  [[ -f "$real_file" ]] || { rm -f "$site"; continue; }
  if grep -q "^location" "$real_file" 2>/dev/null && ! grep -q "^server" "$real_file" 2>/dev/null; then
    base=$(basename "$site" | sed 's/^secubox-//')
    mkdir -p "${ROOTFS}/etc/nginx/secubox.d"
    cp "$real_file" "${ROOTFS}/etc/nginx/secubox.d/${base}.conf" 2>/dev/null || true
    rm -f "$site"
  fi
done

# Test nginx configuration
if chroot "${ROOTFS}" nginx -t 2>&1; then
  ok "Nginx configuration valid"
else
  warn "Nginx configuration has errors (will be fixed at firstboot)"
fi

# Clean apt cache (keep lists for potential future use)
chroot "${ROOTFS}" apt-get clean

# Enable nginx for API proxying (certs already generated earlier)
ln -sf /usr/lib/systemd/system/nginx.service \
  "${ROOTFS}/etc/systemd/system/multi-user.target.wants/nginx.service" 2>/dev/null || true

ok "SecuBox packages installed"

# ══════════════════════════════════════════════════════════════════
# Step 6: Raspberry Pi boot configuration
# ══════════════════════════════════════════════════════════════════
log "6/7 Configuring Pi bootloader..."

# config.txt for Pi 400
mkdir -p "${ROOTFS}/boot/firmware"
cat > "${ROOTFS}/boot/firmware/config.txt" <<EOF
# SecuBox Raspberry Pi 400 Configuration
# Pi 4/400 ARM64 Boot Configuration

[all]
# Use 64-bit kernel
arm_64bit=1

# Kernel (Debian naming) - initramfs added later if available
kernel=vmlinuz
# initramfs line added dynamically if initrd.img exists

# Automatically load appropriate DTB
# For Pi 400, the firmware will load bcm2711-rpi-400.dtb

[pi4]
# Pi 4 specific settings
max_framebuffers=2

[pi400]
# Pi 400 specific settings (Pi 400 runs cooler, can handle more)
arm_boost=1

[all]
# Display
hdmi_force_hotplug=1
disable_overscan=1

# GPU memory (64MB for headless, 128-256 for desktop)
gpu_mem=64

# Serial console for debugging
enable_uart=1
dtoverlay=disable-bt

# USB boot mode (already enabled on Pi 400 EEPROM)
# program_usb_boot_mode=1

# Camera/Display (disabled by default)
# camera_auto_detect=1
# display_auto_detect=1
EOF

# cmdline.txt - Pi can boot WITHOUT initrd using root= directly
# This avoids slow initramfs generation under QEMU
cat > "${ROOTFS}/boot/firmware/cmdline.txt" <<EOF
console=serial0,115200 console=tty1 root=/dev/mmcblk0p2 rootfstype=ext4 rootwait fsck.repair=yes quiet
EOF

# Check if initrd already exists from kernel install
if ls "${ROOTFS}/boot/initrd.img-"* >/dev/null 2>&1; then
  log "initrd already exists from kernel install"
  # Update config.txt to use it
  sed -i 's/^initramfs.*/initramfs initrd.img followkernel/' "${ROOTFS}/boot/firmware/config.txt"
else
  # No initrd - configure for direct boot (faster, simpler)
  log "No initrd - configuring direct boot (no initramfs needed for Pi)"
  # Remove initramfs line from config.txt since we're booting directly
  sed -i '/^initramfs/d' "${ROOTFS}/boot/firmware/config.txt"

  # Generate initrd (required for module loading)
  # QEMU arm64 emulation is slow - allow 5 minutes
  log "Generating initramfs (this may take 3-5 minutes under QEMU)..."
  KVER=$(ls "${ROOTFS}/lib/modules/" 2>/dev/null | head -1)
  if [[ -n "$KVER" ]]; then
    # Create wrapper script to ensure PATH is set for mkinitramfs
    cat > "${ROOTFS}/tmp/gen-initrd.sh" <<INITRD
#!/bin/bash
export PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
update-initramfs -c -k ${KVER}
INITRD
    chmod +x "${ROOTFS}/tmp/gen-initrd.sh"

    # Use timeout to prevent infinite hanging
    if timeout 300 chroot "${ROOTFS}" /tmp/gen-initrd.sh; then
      # Verify initrd was actually created and has content
      if [[ -s "${ROOTFS}/boot/initrd.img-${KVER}" ]]; then
        INITRD_SIZE=$(du -h "${ROOTFS}/boot/initrd.img-${KVER}" | cut -f1)
        ok "initrd generated successfully (${INITRD_SIZE})"
        sed -i '/^\[all\]/a initramfs initrd.img followkernel' "${ROOTFS}/boot/firmware/config.txt"
      else
        warn "initrd file empty or missing - Pi may not boot!"
      fi
    else
      warn "initrd generation failed or timed out after 5 minutes!"
      warn "Pi will boot but kernel modules won't load dynamically."
      warn "For full functionality, rebuild on native ARM64 hardware."
      # Don't exit - Pi can still boot, just with reduced functionality
    fi
  else
    err "No kernel modules found in ${ROOTFS}/lib/modules/"
    exit 1
  fi
fi

ok "Pi bootloader configured"

# ══════════════════════════════════════════════════════════════════
# Step 7: Create image
# ══════════════════════════════════════════════════════════════════
log "7/7 Creating bootable image..."

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

# Ensure kernel sees partitions (race condition workaround)
partprobe "${LOOP}" 2>/dev/null || true
sleep 1

# Wait for partition devices to appear
for i in {1..10}; do
  [[ -b "${LOOP}p1" ]] && break
  sleep 1
done
[[ -b "${LOOP}p1" ]] || err "Partition ${LOOP}p1 not found after waiting"

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

# Copy Raspberry Pi firmware files to boot partition
log "Copying Pi firmware files..."

# The raspi-firmware package installs files to /usr/lib/raspi-firmware/ in Debian
FIRMWARE_SRC="${MNT}/usr/lib/raspi-firmware"
if [[ -d "$FIRMWARE_SRC" ]]; then
  # Copy all firmware files (start*.elf, fixup*.dat, bootcode.bin, etc.)
  cp -v "${FIRMWARE_SRC}"/*.elf "${MNT}/boot/firmware/" 2>/dev/null || warn "No .elf files found"
  cp -v "${FIRMWARE_SRC}"/*.dat "${MNT}/boot/firmware/" 2>/dev/null || warn "No .dat files found"
  cp -v "${FIRMWARE_SRC}"/*.bin "${MNT}/boot/firmware/" 2>/dev/null || true
  cp -v "${FIRMWARE_SRC}"/*.dtb "${MNT}/boot/firmware/" 2>/dev/null || true

  # Copy overlays directory
  if [[ -d "${FIRMWARE_SRC}/overlays" ]]; then
    cp -rv "${FIRMWARE_SRC}/overlays" "${MNT}/boot/firmware/"
    ok "Firmware overlays copied"
  fi
  ok "Pi firmware copied from raspi-firmware package"
else
  warn "raspi-firmware not found at ${FIRMWARE_SRC}, trying alternative locations..."
  # Alternative: firmware might be in /boot/firmware already
  if [[ -d "${MNT}/boot/firmware" ]] && ls "${MNT}/boot/firmware/"*.elf >/dev/null 2>&1; then
    ok "Firmware already present in /boot/firmware"
  else
    err "No Raspberry Pi firmware found! Install raspi-firmware package."
  fi
fi

# Copy Device Tree Blobs from kernel package
if ls "${MNT}/usr/lib/linux-image-"*/broadcom/*.dtb >/dev/null 2>&1; then
  cp -v "${MNT}/usr/lib/linux-image-"*/broadcom/bcm*.dtb "${MNT}/boot/firmware/" 2>/dev/null || true
  ok "Kernel DTBs copied"
fi

# Copy kernel and initrd to boot partition
if ls "${MNT}/boot/vmlinuz-"* >/dev/null 2>&1; then
  cp "${MNT}/boot/vmlinuz-"* "${MNT}/boot/firmware/vmlinuz"
  ok "Kernel copied"
else
  err "No kernel found in rootfs"
fi

if ls "${MNT}/boot/initrd.img-"* >/dev/null 2>&1; then
  cp "${MNT}/boot/initrd.img-"* "${MNT}/boot/firmware/initrd.img"
  # Add initramfs line to config.txt since we have an initrd
  if ! grep -q "^initramfs" "${MNT}/boot/firmware/config.txt"; then
    sed -i '/^kernel=vmlinuz/a initramfs initrd.img followkernel' "${MNT}/boot/firmware/config.txt"
  fi
  ok "Initrd copied and config.txt updated"
else
  log "No initrd - Pi will boot directly (this is OK)"
  # Ensure no initramfs line in config.txt
  sed -i '/^initramfs/d' "${MNT}/boot/firmware/config.txt"
fi

# Verify critical boot files
log "Verifying boot files..."
MISSING_FILES=0
for f in start4.elf fixup4.dat vmlinuz; do
  if [[ ! -f "${MNT}/boot/firmware/${f}" ]]; then
    warn "Missing: ${f}"
    MISSING_FILES=1
  fi
done
if [[ $MISSING_FILES -eq 0 ]]; then
  ok "All critical boot files present"
else
  warn "Some boot files missing - Pi may not boot!"
fi

# Update fstab with proper UUIDs
BOOT_UUID=$(blkid -s UUID -o value "${LOOP}p1")
ROOT_UUID=$(blkid -s UUID -o value "${LOOP}p2")
cat > "${MNT}/etc/fstab" <<EOF
# SecuBox RPi fstab
UUID=${BOOT_UUID}  /boot/firmware  vfat    defaults          0       2
UUID=${ROOT_UUID}  /               ext4    defaults,noatime  0       1
EOF

# Update cmdline with UUID (splash for Plymouth boot graphics)
cat > "${MNT}/boot/firmware/cmdline.txt" <<EOF
console=serial0,115200 console=tty1 root=UUID=${ROOT_UUID} rootfstype=ext4 elevator=deadline fsck.repair=yes rootwait quiet splash
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
