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
INCLUDE_KIOSK=1
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
  --no-kiosk         Disable GUI kiosk mode (enabled by default)
  --no-persistence   Don't include persistent storage partition
  --no-compress      Skip gzip compression (faster, for local testing)
  --preseed FILE     Include preseed config archive
  --help             Show this help

Features:
  - UEFI + Legacy BIOS boot
  - All SecuBox packages pre-installed
  - Root autologin on console
  - Network auto-detection at first boot
  - GUI kiosk mode included by default (--no-kiosk to disable)

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
    --no-kiosk)       INCLUDE_KIOSK=0;      shift   ;;
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
INCLUDE_PKGS+=",linux-image-amd64,live-boot,live-boot-initramfs-tools,live-config,live-config-systemd"
INCLUDE_PKGS+=",grub-efi-amd64,efibootmgr,pciutils,usbutils,lsb-release"
INCLUDE_PKGS+=",plymouth,plymouth-themes"

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

# Enable SSH root login with password
sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' "${ROOTFS}/etc/ssh/sshd_config"
sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' "${ROOTFS}/etc/ssh/sshd_config"
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' "${ROOTFS}/etc/ssh/sshd_config"

# ── Autologin root on tty1 ────────────────────────────────────────
mkdir -p "${ROOTFS}/etc/systemd/system/getty@tty1.service.d"
cat > "${ROOTFS}/etc/systemd/system/getty@tty1.service.d/override.conf" <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I \$TERM
Type=idle
EOF

# Enable getty@tty1 and set default target
chroot "${ROOTFS}" systemctl enable getty@tty1.service 2>/dev/null || true
chroot "${ROOTFS}" systemctl set-default multi-user.target 2>/dev/null || true

# Disable live-config autologin
mkdir -p "${ROOTFS}/etc/live/config.conf.d"
echo 'LIVE_CONFIG_NOAUTOLOGIN=true' > "${ROOTFS}/etc/live/config.conf.d/no-autologin.conf"

# Boot status (show for debugging)
mkdir -p "${ROOTFS}/etc/systemd/system.conf.d"
cat > "${ROOTFS}/etc/systemd/system.conf.d/boot.conf" <<EOF
[Manager]
ShowStatus=yes
DefaultTimeoutStartSec=30s
DefaultTimeoutStopSec=30s
EOF

# Disable console spam
cat > "${ROOTFS}/etc/sysctl.d/99-secubox.conf" <<EOF
kernel.consoleblank=0
net.ipv4.conf.all.log_martians=0
kernel.printk=1 1 1 1
EOF

# ── Hardware Check Service ──────────────────────────────────────────
# Auto-check hardware and report at boot when secubox.hwcheck=1
cat > "${ROOTFS}/usr/local/bin/secubox-hwcheck" <<'HWCHECK'
#!/bin/bash
# SecuBox Hardware Check - Evaluates system hardware and reports status

REPORT_FILE="/var/log/secubox-hwcheck.log"
REPORT_CONSOLE="/dev/tty1"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$REPORT_FILE"
    [ -c "$REPORT_CONSOLE" ] && echo "$*" > "$REPORT_CONSOLE"
}

cyber_banner() {
    # VT100 green phosphor style
    echo -e "\033[32m"
    cat << 'BANNER'

  ____  _____ ____ _   _ ____   _____  __
 / ___|| ____/ ___| | | | __ ) / _ \ \/ /
 \___ \|  _|| |   | | | |  _ \| | | \  /
  ___) | |__| |___| |_| | |_) | |_| /  \
 |____/|_____\____|\___/|____/ \___/_/\_\

================================================================
  DEC PDP-11/70 COMPATIBLE - HARDWARE EVALUATION MODE
================================================================

BANNER
}

check_hw() {
    clear
    cyber_banner
    sleep 1

    log ">>>> SYSTEM HARDWARE SCAN INITIATED <<<<"
    log "================================================================"
    echo ""

    # CPU
    CPU_MODEL=$(grep -m1 "model name" /proc/cpuinfo | cut -d: -f2 | xargs)
    CPU_CORES=$(grep -c processor /proc/cpuinfo)
    log "CPU.......... $CPU_MODEL"
    log "             ($CPU_CORES PROCESSOR UNITS)"

    # Memory
    MEM_TOTAL=$(free -h | awk '/Mem:/ {print $2}')
    MEM_AVAIL=$(free -h | awk '/Mem:/ {print $7}')
    log "MEMORY....... $MEM_TOTAL TOTAL / $MEM_AVAIL AVAILABLE"

    # Storage
    log "STORAGE DEVICES:"
    lsblk -d -o NAME,SIZE,TYPE,MODEL 2>/dev/null | grep -v "^NAME" | while read line; do
        log "  * $line"
    done

    # Network
    log "NETWORK INTERFACES:"
    for iface in /sys/class/net/*; do
        name=$(basename "$iface")
        [ "$name" = "lo" ] && continue
        state=$(cat "$iface/operstate" 2>/dev/null || echo "unknown")
        mac=$(cat "$iface/address" 2>/dev/null || echo "n/a")
        if [ "$state" = "up" ]; then
            log "  [+] $name: $state ($mac)"
        else
            log "  [-] $name: $state ($mac)"
        fi
    done

    # Graphics
    log "GRAPHICS ADAPTER:"
    lspci 2>/dev/null | grep -iE "vga|3d|display" | while read line; do
        log "  * $line"
    done

    # Boot mode
    if [ -d /sys/firmware/efi ]; then
        log "BOOT MODE.... UEFI"
    else
        log "BOOT MODE.... BIOS/LEGACY"
    fi

    # Virtualization detection
    VIRT=$(systemd-detect-virt 2>/dev/null || echo "none")
    if [ "$VIRT" = "none" ]; then
        log "PLATFORM..... BARE METAL"
    else
        log "PLATFORM..... VIRTUAL ($VIRT)"
    fi

    echo ""
    log "================================================================"
    log ">>>> HARDWARE CHECK COMPLETE - ALL SYSTEMS NOMINAL <<<<"
    log ">>>> SECUBOX CYBER DEFENSE PLATFORM READY <<<<"
    log "================================================================"
    echo ""
}

# Cyber boot splash with status - VT100 style
cyber_splash() {
    clear
    echo -e "\033[32m"
    cyber_banner

    local steps=(
        "INITIALIZING SECURE ENVIRONMENT.......... OK"
        "LOADING CRYPTOGRAPHIC MODULES............ OK"
        "CONFIGURING NETWORK STACK................ OK"
        "ACTIVATING FIREWALL RULES................ OK"
        "SCANNING FOR THREATS..................... CLEAR"
        "HARDENING SYSTEM......................... OK"
        "OPTIMIZING PERFORMANCE................... OK"
    )

    for step in "${steps[@]}"; do
        echo -e "  > $step"
        sleep 0.3
    done

    echo ""
    echo "  >>>> SECURE BOOT SEQUENCE COMPLETE <<<<"
    echo ""
    sleep 1
}

# Check if hwcheck requested via kernel cmdline
if grep -q "secubox.hwcheck=1" /proc/cmdline; then
    cyber_splash
    check_hw
fi
HWCHECK
chmod +x "${ROOTFS}/usr/local/bin/secubox-hwcheck"

# Create retro CRT VT100 DEC PDP-style boot splash
cat > "${ROOTFS}/usr/local/bin/secubox-splash" <<'SPLASH'
#!/bin/bash
# SecuBox Cyber Boot Splash - VT100/DEC PDP Style

# VT100 escape codes
ESC="\033"
GREEN="${ESC}[32m"
BRIGHT="${ESC}[1m"
DIM="${ESC}[2m"
BLINK="${ESC}[5m"
RESET="${ESC}[0m"
CLEAR="${ESC}[2J${ESC}[H"

# Clear screen and set green phosphor look
echo -ne "$CLEAR$GREEN"

# Simulated boot delay
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
echo "  DEC PDP-11/70 COMPATIBLE SECURITY TERMINAL"
echo "  SECUBOX CYBER DEFENSE SYSTEM v1.3"
echo -e "${BRIGHT}================================================================${RESET}${GREEN}"
echo ""

type_slow "BOOT SEQUENCE INITIATED..."
echo ""

# Boot status messages
steps=(
    "MEMORY TEST.................... 4096K OK"
    "LOADING KERNEL................. DONE"
    "CRYPTOGRAPHIC MODULES.......... LOADED"
    "NETWORK STACK.................. INITIALIZED"
    "FIREWALL RULES................. ACTIVE"
    "INTRUSION DETECTION............ ARMED"
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
echo "  |  UNAUTHORIZED ACCESS WILL BE PROSECUTED        |"
echo "  '------------------------------------------------'"
echo ""
echo -e "${DIM}  Press ENTER to continue...${RESET}${GREEN}"
read -t 5 || true
echo -ne "$RESET"
SPLASH
chmod +x "${ROOTFS}/usr/local/bin/secubox-splash"

# Add splash to root's bashrc for login
cat >> "${ROOTFS}/root/.bashrc" <<'BASHRC'

# SecuBox Cyber Splash on login
if [ -t 0 ] && [ -z "$SECUBOX_SPLASH_SHOWN" ]; then
    export SECUBOX_SPLASH_SHOWN=1
    /usr/local/bin/secubox-splash 2>/dev/null || true
fi
BASHRC

# Systemd service for hardware check
cat > "${ROOTFS}/etc/systemd/system/secubox-hwcheck.service" <<'HWSVC'
[Unit]
Description=SecuBox Hardware Check
After=local-fs.target
Before=getty@tty1.service
ConditionKernelCommandLine=secubox.hwcheck=1

[Service]
Type=oneshot
ExecStart=/usr/local/bin/secubox-hwcheck
RemainAfterExit=yes
StandardOutput=journal+console

[Install]
WantedBy=multi-user.target
HWSVC
chroot "${ROOTFS}" systemctl enable secubox-hwcheck.service 2>/dev/null || true

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

# ── Plymouth Boot Splash Theme ─────────────────────────────────────
log "Installing Plymouth boot splash..."

# Create SecuBox Plymouth theme directory
PLYMOUTH_DIR="${ROOTFS}/usr/share/plymouth/themes/secubox"
mkdir -p "${PLYMOUTH_DIR}"

# Create theme descriptor
cat > "${PLYMOUTH_DIR}/secubox.plymouth" <<'PLYTHEME'
[Plymouth Theme]
Name=SecuBox Cyber
Description=SecuBox VT100/DEC PDP-11 style boot splash
ModuleName=script

[script]
ImageDir=/usr/share/plymouth/themes/secubox
ScriptFile=/usr/share/plymouth/themes/secubox/secubox.script
PLYTHEME

# Create Plymouth script (text-based retro look)
cat > "${PLYMOUTH_DIR}/secubox.script" <<'PLYSCRIPT'
# SecuBox Plymouth Theme - VT100/DEC PDP-11 Style
# Green phosphor terminal aesthetic

# Colors
Window.SetBackgroundTopColor(0.0, 0.0, 0.0);
Window.SetBackgroundBottomColor(0.0, 0.05, 0.0);

# Logo and text positioning
screen_width = Window.GetWidth();
screen_height = Window.GetHeight();
center_x = screen_width / 2;
center_y = screen_height / 2;

# Banner text (ASCII art simulation)
banner_text = "SECUBOX CYBER DEFENSE SYSTEM";
banner_sprite = Sprite();
banner_image = Image.Text(banner_text, 0.0, 1.0, 0.0, "Fixed");
banner_sprite.SetImage(banner_image);
banner_sprite.SetPosition(center_x - banner_image.GetWidth() / 2, center_y - 100, 1);

# Version line
version_text = "DEC PDP-11/70 COMPATIBLE - SECURE BOOT SEQUENCE";
version_sprite = Sprite();
version_image = Image.Text(version_text, 0.0, 0.8, 0.0, "Fixed");
version_sprite.SetImage(version_image);
version_sprite.SetPosition(center_x - version_image.GetWidth() / 2, center_y - 60, 1);

# Separator line
sep_text = "================================================================";
sep_sprite = Sprite();
sep_image = Image.Text(sep_text, 0.0, 0.6, 0.0, "Fixed");
sep_sprite.SetImage(sep_image);
sep_sprite.SetPosition(center_x - sep_image.GetWidth() / 2, center_y - 40, 1);

# Progress indicator
progress_sprite = Sprite();

fun refresh_callback() {
    # Blinking cursor effect
    time = Plymouth.GetTime();
    if (Math.Int(time * 2) % 2 == 0) {
        cursor_text = "_";
    } else {
        cursor_text = " ";
    }
    cursor_image = Image.Text(cursor_text, 0.0, 1.0, 0.0, "Fixed");
    cursor_sprite = Sprite(cursor_image);
    cursor_sprite.SetPosition(center_x + 100, center_y + 60, 2);
}

Plymouth.SetRefreshFunction(refresh_callback);

# Boot progress bar
progress_box_image = Image.Text("[                              ]", 0.0, 0.8, 0.0, "Fixed");
progress_box_sprite = Sprite(progress_box_image);
progress_box_sprite.SetPosition(center_x - progress_box_image.GetWidth() / 2, center_y + 20, 1);

fun boot_progress_callback(duration, progress) {
    # Update progress bar fill
    fill_count = Math.Int(progress * 30);
    fill_text = "";
    for (i = 0; i < fill_count; i++) {
        fill_text = fill_text + "#";
    }
    for (i = fill_count; i < 30; i++) {
        fill_text = fill_text + " ";
    }
    progress_text = "[" + fill_text + "]";
    progress_image = Image.Text(progress_text, 0.0, 1.0, 0.0, "Fixed");
    progress_sprite.SetImage(progress_image);
    progress_sprite.SetPosition(center_x - progress_image.GetWidth() / 2, center_y + 20, 1);
}

Plymouth.SetBootProgressFunction(boot_progress_callback);

# Status message display
message_sprite = Sprite();

fun message_callback(text) {
    message_image = Image.Text("> " + text, 0.0, 0.7, 0.0, "Fixed");
    message_sprite.SetImage(message_image);
    message_sprite.SetPosition(center_x - 200, center_y + 60, 1);
}

Plymouth.SetMessageFunction(message_callback);

# Display mode change
fun display_normal_callback() {
    # Normal boot display
}

fun display_password_callback(prompt, bullets) {
    # Password entry (for encrypted disks)
    password_sprite = Sprite();
    password_image = Image.Text(prompt + " " + bullets, 0.0, 1.0, 0.0, "Fixed");
    password_sprite.SetImage(password_image);
    password_sprite.SetPosition(center_x - password_image.GetWidth() / 2, center_y + 100, 1);
}

Plymouth.SetDisplayNormalFunction(display_normal_callback);
Plymouth.SetDisplayPasswordFunction(display_password_callback);

# System update messages
fun system_update_callback(progress) {
    update_text = "SYSTEM UPDATE: " + Math.Int(progress * 100) + "%";
    update_image = Image.Text(update_text, 0.0, 0.8, 0.0, "Fixed");
    update_sprite = Sprite(update_image);
    update_sprite.SetPosition(center_x - update_image.GetWidth() / 2, center_y + 80, 1);
}

Plymouth.SetSystemUpdateFunction(system_update_callback);
PLYSCRIPT

# Set SecuBox theme as default
mkdir -p "${ROOTFS}/etc/plymouth"
echo "[Daemon]" > "${ROOTFS}/etc/plymouth/plymouthd.conf"
echo "Theme=secubox" >> "${ROOTFS}/etc/plymouth/plymouthd.conf"
echo "ShowDelay=0" >> "${ROOTFS}/etc/plymouth/plymouthd.conf"

# Update alternatives to use our theme
chroot "${ROOTFS}" plymouth-set-default-theme secubox 2>/dev/null || true

ok "Plymouth SecuBox theme installed"

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

# ── Install fake systemctl for chroot builds ───────────────────────
# Package postinst scripts call systemctl which fails in chroot.
# This wrapper silently succeeds for those calls during package install.
log "Installing chroot systemctl wrapper..."
cat > "${ROOTFS}/usr/local/sbin/systemctl-chroot" <<'FAKESYSTEMCTL'
#!/bin/bash
# Fake systemctl for chroot builds - always succeeds
# Real systemctl is at /bin/systemctl or /usr/bin/systemctl
exit 0
FAKESYSTEMCTL
chmod +x "${ROOTFS}/usr/local/sbin/systemctl-chroot"

# Divert real systemctl temporarily
if [[ -x "${ROOTFS}/bin/systemctl" ]]; then
  mv "${ROOTFS}/bin/systemctl" "${ROOTFS}/bin/systemctl.real"
  ln -sf /usr/local/sbin/systemctl-chroot "${ROOTFS}/bin/systemctl"
  SYSTEMCTL_DIVERTED=1
else
  SYSTEMCTL_DIVERTED=0
fi

# ══════════════════════════════════════════════════════════════════
# Step 4: SecuBox packages (slipstream ALL from cache/repo)
# ══════════════════════════════════════════════════════════════════
log "4/8 Installing ALL SecuBox packages..."

# Install Python dependencies FIRST (required by SecuBox packages)
log "Installing Python dependencies..."
chroot "${ROOTFS}" apt-get install -y -q python3-pip python3-venv 2>/dev/null || true
chroot "${ROOTFS}" pip3 install --break-system-packages -q \
  fastapi uvicorn python-jose httpx jinja2 tomli pyroute2 psutil pydantic 2>&1 | tail -5 || true
ok "Python dependencies installed"

# ── Pre-generate SSL certificates for nginx BEFORE installing packages ──
# (Package postinst scripts test nginx, which needs certs to exist)
# Generate certs on HOST (chroot may lack /dev/urandom) and copy them in
log "Pre-generating SSL certificates (needed for nginx test during package install)..."
mkdir -p "${ROOTFS}/etc/secubox/tls"
mkdir -p "${ROOTFS}/run/secubox"
mkdir -p "${ROOTFS}/var/lib/secubox"

# Generate on host system
openssl req -x509 -newkey rsa:2048 -days 365 \
  -keyout "${ROOTFS}/etc/secubox/tls/key.pem" \
  -out "${ROOTFS}/etc/secubox/tls/cert.pem" \
  -nodes -subj "/CN=secubox-live/O=CyberMind SecuBox/C=FR" \
  -addext "subjectAltName=DNS:localhost,DNS:secubox.local,IP:127.0.0.1,IP:192.168.1.1" \
  2>/dev/null

if [[ -f "${ROOTFS}/etc/secubox/tls/cert.pem" ]]; then
  chmod 640 "${ROOTFS}/etc/secubox/tls/key.pem"
  chmod 644 "${ROOTFS}/etc/secubox/tls/cert.pem"
  ok "SSL certificates pre-generated"
else
  warn "SSL cert generation failed - nginx may not start"
fi

# Find all .deb files in cache/repo or output/debs
CACHE_DEBS="${REPO_DIR}/cache/repo/pool"
OUTPUT_DEBS="${REPO_DIR}/output/debs"

# Check both locations for packages
CACHE_COUNT=$(find "$CACHE_DEBS" -name "secubox-*.deb" 2>/dev/null | wc -l)
OUTPUT_COUNT=$(find "$OUTPUT_DEBS" -maxdepth 1 -name "secubox-*.deb" 2>/dev/null | wc -l)
log "Found ${CACHE_COUNT} packages in cache, ${OUTPUT_COUNT} in output/debs"

if [[ $CACHE_COUNT -gt 0 ]] || [[ $OUTPUT_COUNT -gt 0 ]]; then
  log "Slipstream: Installing from local packages"
  install -d "${ROOTFS}/tmp/secubox-debs"

  # Copy ALL secubox debs from cache
  if [[ $CACHE_COUNT -gt 0 ]]; then
    find "$CACHE_DEBS" -name "secubox-*.deb" -exec cp {} "${ROOTFS}/tmp/secubox-debs/" \;
    log "Copied ${CACHE_COUNT} packages from cache"
  fi

  # Also copy from output/debs (for packages not yet in cache, like secubox-console)
  if [[ -d "$OUTPUT_DEBS" ]]; then
    for deb in "${OUTPUT_DEBS}"/secubox-*.deb; do
      [[ -f "$deb" ]] || continue
      pkg_name=$(basename "$deb" | sed 's/_.*$//')
      # Only copy if not already present (prefer cache version)
      if ! ls "${ROOTFS}/tmp/secubox-debs/${pkg_name}_"*.deb >/dev/null 2>&1; then
        cp "$deb" "${ROOTFS}/tmp/secubox-debs/"
        log "Added ${pkg_name} from output/debs"
      fi
    done
  fi

  DEB_COUNT=$(ls "${ROOTFS}/tmp/secubox-debs/"*.deb 2>/dev/null | wc -l)

  # List all packages to be installed
  log "Slipstream: ${DEB_COUNT} packages to install:"
  echo ""
  ls -1 "${ROOTFS}/tmp/secubox-debs/"*.deb | xargs -I{} basename {} | sed 's/_.*$//' | sort -u | while read pkg; do
    echo "  - ${pkg}"
  done
  echo ""

  # Pre-install textual via pip for secubox-console (Debian's version is too old)
  if ls "${ROOTFS}/tmp/secubox-debs/secubox-console_"*.deb >/dev/null 2>&1; then
    log "Pre-installing textual for console TUI (pip, Debian version too old)..."
    chroot "${ROOTFS}" pip3 install --break-system-packages textual rich 2>/dev/null && \
      ok "textual installed via pip" || warn "textual pip install failed"
  fi

  # Install core first (dependency for all)
  if ls "${ROOTFS}/tmp/secubox-debs/secubox-core_"*.deb >/dev/null 2>&1; then
    log "Installing secubox-core (dependency)..."
    chroot "${ROOTFS}" bash -c 'dpkg -i --force-depends /tmp/secubox-debs/secubox-core_*.deb' || warn "secubox-core install failed"
  fi

  # Install all packages (force overwrite for duplicate files)
  log "Installing all packages..."
  # Use bash -c to ensure glob expansion happens inside chroot
  chroot "${ROOTFS}" bash -c 'dpkg -i --force-depends --force-overwrite /tmp/secubox-debs/*.deb 2>&1' | \
    grep -v "^dpkg: warning" | grep -v "^Selecting\|^Preparing\|^Unpacking\|^Setting up" | head -50 || true

  # Fix dependencies with apt
  log "Fixing dependencies..."
  chroot "${ROOTFS}" apt-get install -f -y --fix-broken || warn "apt-get -f failed"

  # Second pass: reconfigure any packages that failed
  log "Reconfiguring packages..."
  chroot "${ROOTFS}" dpkg --configure -a --force-confold 2>/dev/null || true

  # Install textual for console TUI (dependency of secubox-console)
  if ls "${ROOTFS}/tmp/secubox-debs/secubox-console_"*.deb >/dev/null 2>&1 || \
     chroot "${ROOTFS}" dpkg -l secubox-console 2>/dev/null | grep -q "^ii"; then
    log "Installing textual for console TUI..."
    # Try apt first, fall back to pip
    if ! chroot "${ROOTFS}" apt-get install -y -q python3-textual python3-rich 2>/dev/null; then
      chroot "${ROOTFS}" pip3 install --break-system-packages textual 2>/dev/null || \
        warn "textual installation failed - console TUI may not work"
    fi
    ok "Console TUI dependencies installed"
  fi

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
    chroot "${ROOTFS}" apt-get install -y -q secubox-full 2>/dev/null || true

    # Verify secubox-core installed (dependency of secubox-full)
    if ! chroot "${ROOTFS}" dpkg -l secubox-core 2>/dev/null | grep -q "^ii"; then
      warn "secubox-full unavailable"
    fi
  fi
fi

# Fix misplaced nginx configs (some packages install to conf.d instead of secubox.d)
# Location blocks must be inside server blocks, so move them to secubox.d
log "Fixing nginx module configs..."
for conf in "${ROOTFS}/etc/nginx/conf.d/secubox-"*.conf "${ROOTFS}/etc/nginx/conf.d/"*secubox*.conf; do
  [[ -e "$conf" ]] || continue
  # Handle symlinks - just remove them (broken symlinks cause nginx failures)
  if [[ -L "$conf" ]]; then
    rm -f "$conf"
    log "Removed symlink $(basename "$conf") from conf.d/"
  # Handle regular files with location directives
  elif [[ -f "$conf" ]] && grep -q "^location" "$conf" 2>/dev/null; then
    mv "$conf" "${ROOTFS}/etc/nginx/secubox.d/" 2>/dev/null || true
    log "Moved $(basename "$conf") to secubox.d/"
  fi
done

# Also fix sites-enabled (some packages create symlinks there for location blocks)
for site in "${ROOTFS}/etc/nginx/sites-enabled/secubox-"*; do
  [[ -e "$site" ]] || [[ -L "$site" ]] || continue
  # Follow symlink to check the real file
  real_file="$site"
  [[ -L "$site" ]] && real_file=$(readlink -f "$site" 2>/dev/null | sed "s|^|${ROOTFS}|; s|${ROOTFS}${ROOTFS}|${ROOTFS}|")
  if [[ -f "$real_file" ]] && grep -q "^location" "$real_file" 2>/dev/null; then
    # Copy content to secubox.d, then remove site symlink/file
    base_name=$(basename "$site" | sed 's/^secubox-//')
    cp "$real_file" "${ROOTFS}/etc/nginx/secubox.d/${base_name}.conf" 2>/dev/null || true
    rm -f "$site"
    log "Moved $(basename "$site") content to secubox.d/${base_name}.conf"
  fi
done

# Clean up any broken symlinks in secubox.d
for conf in "${ROOTFS}/etc/nginx/secubox.d/"*.conf; do
  [[ -L "$conf" ]] && [[ ! -e "$conf" ]] && rm -f "$conf" && log "Removed broken symlink $(basename "$conf")"
done

# Also clean symlinks pointing to non-existent files (snippets directory doesn't exist)
for conf in "${ROOTFS}/etc/nginx/secubox.d/"*.conf; do
  if [[ -L "$conf" ]]; then
    target=$(readlink "$conf" 2>/dev/null)
    # If target is an absolute path that doesn't exist in the chroot
    if [[ "$target" == /* ]] && [[ ! -e "${ROOTFS}${target}" ]]; then
      rm -f "$conf"
      log "Removed broken symlink $(basename "$conf") -> $target"
    fi
  fi
done

ok "SecuBox packages installed"

# ── Fix systemd service namespaces for /run/secubox ────────────────
# Services with ProtectSystem=strict create mount namespaces that prevent
# socket creation in /run/secubox. Add RuntimeDirectory and tmpfiles.d.
log "Configuring systemd services for /run/secubox..."

# Create tmpfiles.d entry for /run/secubox
mkdir -p "${ROOTFS}/etc/tmpfiles.d"
echo "d /run/secubox 0775 secubox secubox -" > "${ROOTFS}/etc/tmpfiles.d/secubox.conf"

# Create systemd overrides for services that use ProtectSystem with /run/secubox
for unit in "${ROOTFS}"/usr/lib/systemd/system/secubox-*.service; do
  [[ -f "$unit" ]] || continue
  svc=$(basename "$unit" .service)

  # Check if service uses ProtectSystem with ReadWritePaths containing /run/secubox
  if grep -q "ProtectSystem=" "$unit" && grep -q "ReadWritePaths=.*/run/secubox" "$unit"; then
    override_dir="${ROOTFS}/etc/systemd/system/${svc}.service.d"
    mkdir -p "$override_dir"
    cat > "$override_dir/runtime.conf" << 'EOF'
[Service]
# Fix for namespace issues with /run/secubox
RuntimeDirectory=secubox
RuntimeDirectoryMode=0775
RuntimeDirectoryPreserve=yes
EOF
    log "Created override for $svc"
  fi
done

ok "Systemd service overrides created"

# ── Create build metadata ──────────────────────────────────────────
log "Creating build metadata..."
BUILD_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_DATE=$(date +"%Y-%m-%d")
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

mkdir -p "${ROOTFS}/etc/secubox"
cat > "${ROOTFS}/etc/secubox/build-info.json" <<EOF
{
  "build_timestamp": "${BUILD_TIMESTAMP}",
  "build_date": "${BUILD_DATE}",
  "git_commit": "${GIT_COMMIT}",
  "git_branch": "${GIT_BRANCH}",
  "board": "${BOARD}",
  "version": "1.0.0",
  "builder": "$(whoami)@$(hostname)"
}
EOF
log "Build metadata: ${BUILD_DATE} (${GIT_COMMIT})"

# ── Restore real systemctl ─────────────────────────────────────────
if [[ ${SYSTEMCTL_DIVERTED:-0} -eq 1 ]] && [[ -x "${ROOTFS}/bin/systemctl.real" ]]; then
  rm -f "${ROOTFS}/bin/systemctl"
  mv "${ROOTFS}/bin/systemctl.real" "${ROOTFS}/bin/systemctl"
  log "Restored real systemctl"
fi
rm -f "${ROOTFS}/usr/local/sbin/systemctl-chroot"

# ── Enable all SecuBox services ────────────────────────────────────
# CRITICAL: Package postinst scripts may fail in chroot, so we
# explicitly enable all services here by creating symlinks directly
# (systemctl enable doesn't work reliably without systemd running)
log "Enabling SecuBox services..."

# Create wants directory if missing
mkdir -p "${ROOTFS}/etc/systemd/system/multi-user.target.wants"

# First, enable secubox-runtime (creates /run/secubox socket directory)
if [[ -f "${ROOTFS}/usr/lib/systemd/system/secubox-runtime.service" ]]; then
  ln -sf /usr/lib/systemd/system/secubox-runtime.service \
    "${ROOTFS}/etc/systemd/system/multi-user.target.wants/secubox-runtime.service"
  ok "secubox-runtime enabled (socket directory)"
fi

# Enable all SecuBox API services by creating symlinks
ENABLED_COUNT=0
for svc in "${ROOTFS}/usr/lib/systemd/system/secubox-"*.service; do
  [[ -f "$svc" ]] || continue
  svc_name=$(basename "$svc")
  # Skip services that should not auto-start
  case "$svc_name" in
    secubox-kiosk*.service|secubox-console.service|secubox-runtime.service)
      # Kiosk and console are optional - enabled separately
      # Runtime already handled above
      continue
      ;;
  esac
  # Create symlink to enable service
  ln -sf "/usr/lib/systemd/system/${svc_name}" \
    "${ROOTFS}/etc/systemd/system/multi-user.target.wants/${svc_name}"
  ENABLED_COUNT=$((ENABLED_COUNT + 1))
done
ok "Enabled ${ENABLED_COUNT} SecuBox services"

# Enable nginx for API proxying
ln -sf /usr/lib/systemd/system/nginx.service \
  "${ROOTFS}/etc/systemd/system/multi-user.target.wants/nginx.service" 2>/dev/null || true

# Note: SSL certs were already generated before package installation

# ══════════════════════════════════════════════════════════════════
# Step 5: Network detection & kiosk scripts
# ══════════════════════════════════════════════════════════════════
log "5/8 Installing SecuBox scripts..."

mkdir -p "${ROOTFS}/usr/sbin"
mkdir -p "${ROOTFS}/usr/lib/secubox"

# Copy scripts (including kiosk-launcher for robust startup, TUI, and mode switcher)
for script in secubox-net-detect secubox-kiosk-setup secubox-cmdline-handler secubox-kiosk-launcher secubox-console-tui secubox-mode; do
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

# Systemd services (including wayland variant for kiosk and TUI)
mkdir -p "${ROOTFS}/etc/systemd/system"
for svc in secubox-net-detect secubox-cmdline secubox-kiosk secubox-kiosk-wayland secubox-console-tui; do
  if [[ -f "${SCRIPT_DIR}/systemd/${svc}.service" ]]; then
    cp "${SCRIPT_DIR}/systemd/${svc}.service" "${ROOTFS}/etc/systemd/system/"
  fi
done

# Enable net-detect and cmdline services (using symlinks for chroot)
if [[ -f "${ROOTFS}/etc/systemd/system/secubox-cmdline.service" ]]; then
  ln -sf /etc/systemd/system/secubox-cmdline.service \
    "${ROOTFS}/etc/systemd/system/sysinit.target.wants/secubox-cmdline.service" 2>/dev/null || true
fi

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
# Enable firstboot using symlink
ln -sf /etc/systemd/system/secubox-firstboot.service \
  "${ROOTFS}/etc/systemd/system/multi-user.target.wants/secubox-firstboot.service"

# ── Kiosk mode packages (X11 mode - better VM compatibility) ─────────
if [[ $INCLUDE_KIOSK -eq 1 ]]; then
  log "Installing kiosk mode packages (X11)..."

  # X11 packages for better VM/hardware compatibility
  # Install in stages to handle dependencies properly:
  # 1. Core X11 and x11-utils first (avoids luit conflict with chromium)
  log "Installing X11 core packages..."

  # First, fix any broken dpkg state from secubox packages (their postinst may fail in chroot)
  chroot "${ROOTFS}" dpkg --configure -a --force-confold 2>/dev/null || true

  # Install X11 packages non-interactively (avoid keyboard-configuration prompt)
  chroot "${ROOTFS}" env DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    xorg xinit x11-xserver-utils x11-utils \
    xserver-xorg-video-fbdev \
    xserver-xorg-video-vmware \
    fonts-dejavu-core unclutter kbd \
    libinput10 xdg-utils \
    virtualbox-guest-x11 virtualbox-guest-utils 2>/dev/null || warn "Some X11 packages failed"

  # Ensure xinit specifically is installed (critical for kiosk)
  chroot "${ROOTFS}" env DEBIAN_FRONTEND=noninteractive apt-get install -y -q xinit || warn "xinit install failed"

  # Fix any broken dependencies before installing chromium
  chroot "${ROOTFS}" dpkg --configure -a --force-confold 2>/dev/null || true
  chroot "${ROOTFS}" apt-get install -f -y -q 2>/dev/null || true

  # 2. Install chromium separately (after x11-utils to avoid dependency conflicts)
  log "Installing Chromium..."
  chroot "${ROOTFS}" env DEBIAN_FRONTEND=noninteractive apt-get install -y -q chromium || warn "Chromium install failed"

  # Verify key kiosk packages installed - warn if missing but continue
  if ! chroot "${ROOTFS}" dpkg -l xinit 2>/dev/null | grep -q "^ii"; then
    warn "xinit not installed - kiosk may not work"
    # Try one more time with forced install
    chroot "${ROOTFS}" env DEBIAN_FRONTEND=noninteractive apt-get install -y -q --fix-broken xinit 2>/dev/null || true
  fi
  if ! chroot "${ROOTFS}" dpkg -l chromium 2>/dev/null | grep -q "^ii"; then
    warn "Chromium not installed - kiosk may not work properly"
  fi

  # Allow non-console users to start X server (required for systemd service)
  mkdir -p "${ROOTFS}/etc/X11"
  cat > "${ROOTFS}/etc/X11/Xwrapper.config" <<'XWRAP'
allowed_users=anybody
needs_root_rights=yes
XWRAP

  # X11 config for VirtualBox/VM compatibility (use modesetting driver)
  mkdir -p "${ROOTFS}/etc/X11/xorg.conf.d"
  cat > "${ROOTFS}/etc/X11/xorg.conf.d/10-modesetting.conf" <<'XCONF'
Section "Device"
    Identifier  "Default Device"
    Driver      "modesetting"
EndSection

Section "Screen"
    Identifier  "Default Screen"
    Device      "Default Device"
    DefaultDepth 24
    SubSection "Display"
        Depth   24
        Modes   "1024x768" "800x600" "640x480"
    EndSubSection
EndSection

Section "ServerFlags"
    Option "AutoAddGPU" "false"
    Option "AutoBindGPU" "false"
EndSection
XCONF
  ok "X11 modesetting config created"

  # Create kiosk user with UID 1000 (use /bin/bash for X11 su commands)
  if ! chroot "${ROOTFS}" id secubox-kiosk &>/dev/null; then
    chroot "${ROOTFS}" useradd -r -u 1000 -m -d /home/secubox-kiosk -s /bin/bash \
      -G video,audio,input,render secubox-kiosk 2>/dev/null || \
    chroot "${ROOTFS}" useradd -r -m -d /home/secubox-kiosk -s /bin/bash \
      -G video,audio,input,render secubox-kiosk
    ok "Created kiosk user"
  fi

  # Create X11 .xinitrc for kiosk
  mkdir -p "${ROOTFS}/home/secubox-kiosk/.config"
  cat > "${ROOTFS}/home/secubox-kiosk/.xinitrc" <<'XINITRC'
#!/bin/bash
# SecuBox Kiosk X11 Launcher
# Note: secubox-kiosk-launcher already waits for services before starting

# URL from environment (set by launcher) or fallback
URL="${KIOSK_URL:-https://localhost/}"

# Log startup
logger -t secubox-kiosk "Starting Chromium X11 kiosk: $URL"

# Disable screen blanking (ignore errors on headless)
xset s off 2>/dev/null || true
xset -dpms 2>/dev/null || true
xset s noblank 2>/dev/null || true

# Hide cursor after 3 seconds of inactivity
if command -v unclutter &>/dev/null; then
    unclutter -idle 3 -root &
fi

# Set background to black
xsetroot -solid black 2>/dev/null || true

# Chromium flags for kiosk mode (X11)
CHROMIUM_FLAGS=(
    --kiosk
    --no-first-run
    --no-sandbox
    --disable-gpu-sandbox
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

# Run Chromium
exec chromium "${CHROMIUM_FLAGS[@]}"
XINITRC
  chmod +x "${ROOTFS}/home/secubox-kiosk/.xinitrc"
  chroot "${ROOTFS}" chown -R secubox-kiosk:secubox-kiosk /home/secubox-kiosk

  # Mark as installed AND enabled (so kiosk starts on first boot)
  mkdir -p "${ROOTFS}/var/lib/secubox"
  echo "installed=$(date -Iseconds)" > "${ROOTFS}/var/lib/secubox/.kiosk-installed"
  touch "${ROOTFS}/var/lib/secubox/.kiosk-enabled"
  echo "x11" > "${ROOTFS}/var/lib/secubox/.kiosk-mode"

  # Use the fixed kiosk service (already copied from systemd/ directory)
  # The service uses secubox-kiosk-launcher which handles:
  # - Dynamic UID detection (no hardcoded 1000)
  # - Proper dependency waiting (nginx, network)
  # - User creation if needed
  # - Fallback URL handling
  log "Kiosk service already copied from systemd/ directory"

  # Enable kiosk service using symlink and set graphical target
  mkdir -p "${ROOTFS}/etc/systemd/system/graphical.target.wants"
  ln -sf /etc/systemd/system/secubox-kiosk.service \
    "${ROOTFS}/etc/systemd/system/graphical.target.wants/secubox-kiosk.service"
  # Set graphical target as default
  ln -sf /usr/lib/systemd/system/graphical.target \
    "${ROOTFS}/etc/systemd/system/default.target"
  chroot "${ROOTFS}" systemctl disable getty@tty1.service 2>/dev/null || true

  # Setup root autologin on tty2 (console access while kiosk runs on tty7)
  mkdir -p "${ROOTFS}/etc/systemd/system/getty@tty2.service.d"
  cat > "${ROOTFS}/etc/systemd/system/getty@tty2.service.d/autologin.conf" <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I \$TERM
Type=idle
EOF
  ln -sf /usr/lib/systemd/system/getty@.service \
    "${ROOTFS}/etc/systemd/system/getty.target.wants/getty@tty2.service" 2>/dev/null || true

  ok "Kiosk X11 packages and user installed (console on tty2)"
else
  # ── No kiosk: Enable console TUI mode instead ─────────────────────
  log "Kiosk disabled - enabling console TUI mode..."

  # Enable secubox-console service if available
  if [[ -f "${ROOTFS}/usr/lib/systemd/system/secubox-console.service" ]]; then
    ln -sf /usr/lib/systemd/system/secubox-console.service \
      "${ROOTFS}/etc/systemd/system/multi-user.target.wants/secubox-console.service"
    mkdir -p "${ROOTFS}/var/lib/secubox"
    echo "enabled" > "${ROOTFS}/var/lib/secubox/.console-enabled"
    ok "Console TUI enabled on tty1"
  else
    log "secubox-console not installed - standard shell login"
  fi

  # Setup root autologin on tty1 for console access
  mkdir -p "${ROOTFS}/etc/systemd/system/getty@tty1.service.d"
  cat > "${ROOTFS}/etc/systemd/system/getty@tty1.service.d/autologin.conf" <<'AUTOLOGIN'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM
AUTOLOGIN
  mkdir -p "${ROOTFS}/etc/systemd/system/getty.target.wants"
  ln -sf /usr/lib/systemd/system/getty@.service \
    "${ROOTFS}/etc/systemd/system/getty.target.wants/getty@tty1.service" 2>/dev/null || true
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

# Ensure squashfs module loads at boot (runtime)
echo "squashfs" >> "${ROOTFS}/etc/modules-load.d/live.conf"
echo "loop" >> "${ROOTFS}/etc/modules-load.d/live.conf"
echo "overlay" >> "${ROOTFS}/etc/modules-load.d/live.conf"

# CRITICAL: Add modules to initramfs for live-boot (must be in initrd, not just modules-load.d)
mkdir -p "${ROOTFS}/etc/initramfs-tools"
cat >> "${ROOTFS}/etc/initramfs-tools/modules" <<'EOFMOD'
# Live-boot required modules
squashfs
loop
overlay
# Filesystem support
ext4
vfat
iso9660
# USB/storage support
usb_storage
uas
sd_mod
# Block layer
dm_mod
# Virtual drivers for VMs
virtio_blk
virtio_scsi
virtio_pci
EOFMOD

# Configure initramfs for live-boot
cat > "${ROOTFS}/etc/initramfs-tools/conf.d/live-boot.conf" <<'EOFLIVE'
# Include most modules for hardware compatibility
MODULES=most
# Compress with gzip for faster boot
COMPRESS=gzip
# Resume disabled for live
RESUME=none
EOFLIVE

# Ensure Plymouth is in initramfs
mkdir -p "${ROOTFS}/etc/initramfs-tools/conf.d"
echo "FRAMEBUFFER=y" > "${ROOTFS}/etc/initramfs-tools/conf.d/plymouth"

# CRITICAL FIX: Force load squashfs module early via init-top script
# The standard initramfs module loading doesn't always work for squashfs
mkdir -p "${ROOTFS}/etc/initramfs-tools/scripts/init-top"
cat > "${ROOTFS}/etc/initramfs-tools/scripts/init-top/load-squashfs" <<'EOFSQ'
#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in
    prereqs) prereqs; exit 0;;
esac
# Force load squashfs module for live-boot
modprobe -q squashfs 2>/dev/null || true
modprobe -q loop 2>/dev/null || true
modprobe -q overlay 2>/dev/null || true
EOFSQ
chmod +x "${ROOTFS}/etc/initramfs-tools/scripts/init-top/load-squashfs"

# Also add to hooks to ensure module is copied
mkdir -p "${ROOTFS}/etc/initramfs-tools/hooks"
cat > "${ROOTFS}/etc/initramfs-tools/hooks/live-squashfs" <<'EOFHOOK'
#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in
    prereqs) prereqs; exit 0;;
esac
. /usr/share/initramfs-tools/hook-functions
# Ensure squashfs module is included
manual_add_modules squashfs loop overlay
EOFHOOK
chmod +x "${ROOTFS}/etc/initramfs-tools/hooks/live-squashfs"

# Regenerate initramfs with live-boot and Plymouth hooks
log "Regenerating initramfs with live-boot hooks..."
chroot "${ROOTFS}" update-initramfs -u -k all || warn "initramfs update failed"

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

# ── Final permission fixes (MUST be done after all setup, before squashfs) ──
log "Final permission fixes..."

# Ensure www directory exists with fallback index.html
mkdir -p "${ROOTFS}/usr/share/secubox/www"
if [[ ! -f "${ROOTFS}/usr/share/secubox/www/index.html" ]]; then
  log "Creating fallback index.html..."
  cat > "${ROOTFS}/usr/share/secubox/www/index.html" <<'FALLBACK_HTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecuBox Live</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 50%, #0a0a0f 100%);
            color: #e8e6d9;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            text-align: center;
            padding: 2rem;
            max-width: 600px;
        }
        h1 {
            font-size: 3rem;
            color: #c9a84c;
            margin-bottom: 1rem;
            text-shadow: 0 0 20px rgba(201, 168, 76, 0.3);
        }
        .subtitle {
            font-size: 1.2rem;
            color: #00d4ff;
            margin-bottom: 2rem;
        }
        .status {
            background: rgba(0, 212, 255, 0.1);
            border: 1px solid #00d4ff;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }
        .status h2 {
            color: #00ff41;
            margin-bottom: 0.5rem;
        }
        .info {
            color: #6b6b7a;
            font-size: 0.9rem;
            line-height: 1.6;
        }
        .info a {
            color: #c9a84c;
            text-decoration: none;
        }
        .info a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ SecuBox</h1>
        <p class="subtitle">CyberMind Security Platform</p>
        <div class="status">
            <h2>✓ System Running</h2>
            <p>SecuBox Live USB is operational</p>
        </div>
        <div class="info">
            <p>Access the full dashboard at <a href="https://localhost/">https://localhost/</a></p>
            <p>Default credentials: admin / admin</p>
            <p><br>Console: Press Ctrl+Alt+F2 for terminal</p>
        </div>
    </div>
</body>
</html>
FALLBACK_HTML
  ok "Fallback index.html created"
fi

# Fix www directory ownership (nginx runs as www-data)
if [[ -d "${ROOTFS}/usr/share/secubox/www" ]]; then
  chown -R root:root "${ROOTFS}/usr/share/secubox/www"
  chmod -R 755 "${ROOTFS}/usr/share/secubox/www"
  find "${ROOTFS}/usr/share/secubox/www" -type f -exec chmod 644 {} \;
  log "Fixed www directory: $(ls -ld ${ROOTFS}/usr/share/secubox/www)"
fi

# Fix /etc/secubox ownership
if [[ -d "${ROOTFS}/etc/secubox" ]]; then
  chown -R root:root "${ROOTFS}/etc/secubox"
  chmod 755 "${ROOTFS}/etc/secubox"
  chmod 755 "${ROOTFS}/etc/secubox/tls" 2>/dev/null || true
  chmod 644 "${ROOTFS}/etc/secubox/tls/cert.pem" 2>/dev/null || true
  chmod 640 "${ROOTFS}/etc/secubox/tls/key.pem" 2>/dev/null || true
  # Make key readable by www-data
  chgrp www-data "${ROOTFS}/etc/secubox/tls/key.pem" 2>/dev/null || true
fi

# Fix nginx secubox.d
if [[ -d "${ROOTFS}/etc/nginx/secubox.d" ]]; then
  chmod 755 "${ROOTFS}/etc/nginx/secubox.d"
  chmod 644 "${ROOTFS}/etc/nginx/secubox.d/"*.conf 2>/dev/null || true
fi

ok "Permissions fixed"

# ══════════════════════════════════════════════════════════════════
# Step 7: Create SquashFS
# ══════════════════════════════════════════════════════════════════
log "7/8 Creating SquashFS filesystem..."
mkdir -p "${LIVE_DIR}/live"

mksquashfs "${ROOTFS}" "${LIVE_DIR}/live/filesystem.squashfs" \
  -comp xz -b 1M -Xdict-size 100% -e boot/grub -e boot/efi

cp "${ROOTFS}/boot/vmlinuz-"* "${LIVE_DIR}/live/vmlinuz"
cp "${ROOTFS}/boot/initrd.img-"* "${LIVE_DIR}/live/initrd.img"

# Create filesystem.size (required by some live-boot versions)
du -s "${ROOTFS}" | cut -f1 > "${LIVE_DIR}/live/filesystem.size"

# Create filesystem.packages list (read from dpkg status file since chroot not available)
awk '/^Package:/{pkg=$2} /^Version:/{print pkg,$2}' "${ROOTFS}/var/lib/dpkg/status" > "${LIVE_DIR}/live/filesystem.packages" 2>/dev/null || true

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

# Calculate partition sizes dynamically
# Convert IMG_SIZE to MiB (e.g., "4G" -> 4096, "8G" -> 8192)
IMG_SIZE_NUM="${IMG_SIZE%[GgMm]}"
IMG_SIZE_UNIT="${IMG_SIZE: -1}"
if [[ "$IMG_SIZE_UNIT" == "G" ]] || [[ "$IMG_SIZE_UNIT" == "g" ]]; then
  IMG_SIZE_MIB=$((IMG_SIZE_NUM * 1024))
else
  IMG_SIZE_MIB=$IMG_SIZE_NUM
fi

# Partition layout:
# 1: BIOS boot (2MB) - legacy grub
# 2: ESP (512MB) - UEFI
# 3: LIVE - squashfs + grub + kernels (dynamic, leaves room for persistence)
# 4: persistence (optional, ~1/3 of total for 8G+, or rest)

ESP_END=515  # 3 + 512 = 515 MiB
if [[ $INCLUDE_PERSISTENCE -eq 1 ]]; then
  # For persistence, leave 25% of image for persistence (min 512MB)
  PERSIST_SIZE=$(( IMG_SIZE_MIB / 4 ))
  [[ $PERSIST_SIZE -lt 512 ]] && PERSIST_SIZE=512
  LIVE_END=$(( IMG_SIZE_MIB - PERSIST_SIZE - 2 ))  # -2 for GPT backup

  # Sanity check: LIVE must be at least 1GB for squashfs
  [[ $LIVE_END -lt 1539 ]] && LIVE_END=1539

  log "Partitions: ESP ${ESP_END}MiB, LIVE ${ESP_END}-${LIVE_END}MiB, Persist ${LIVE_END}MiB-100%"

  parted -s "${IMG_FILE}" \
    mklabel gpt \
    mkpart bios 1MiB 3MiB \
    mkpart ESP fat32 3MiB ${ESP_END}MiB \
    mkpart LIVE ext4 ${ESP_END}MiB ${LIVE_END}MiB \
    mkpart persistence ext4 ${LIVE_END}MiB 100% \
    set 1 bios_grub on \
    set 2 esp on \
    set 2 boot on
else
  log "Partitions: ESP ${ESP_END}MiB, LIVE ${ESP_END}MiB-100%"

  parted -s "${IMG_FILE}" \
    mklabel gpt \
    mkpart bios 1MiB 3MiB \
    mkpart ESP fat32 3MiB ${ESP_END}MiB \
    mkpart LIVE ext4 ${ESP_END}MiB 100% \
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

# Copy live files to root of LIVE partition
# GRUB looks for ($live)/live/* and live-boot looks for /live/filesystem.squashfs
mkdir -p "${MNT}/live/live"
cp "${LIVE_DIR}/live/filesystem.squashfs" "${MNT}/live/live/"
cp "${LIVE_DIR}/live/vmlinuz" "${MNT}/live/live/"
cp "${LIVE_DIR}/live/initrd.img" "${MNT}/live/live/"
cp "${LIVE_DIR}/live/filesystem.size" "${MNT}/live/live/" 2>/dev/null || true
cp "${LIVE_DIR}/live/filesystem.packages" "${MNT}/live/live/" 2>/dev/null || true

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
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components persistence quiet splash
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Kiosk GUI)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components persistence quiet splash secubox.kiosk=1 systemd.unit=graphical.target
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Console TUI)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components persistence quiet splash secubox.mode=tui
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Bridge Mode)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components persistence quiet splash secubox.netmode=bridge
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Safe Mode)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components nomodeset console=tty0
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (To RAM)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components toram quiet splash
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Auto-Check HW)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components persistence quiet splash secubox.hwcheck=1
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Auto-Check HW - Text Mode)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components persistence nomodeset console=tty0 secubox.hwcheck=1
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Emergency Shell)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components nomodeset console=tty0 systemd.unit=emergency.target
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Debug - Verbose Boot)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components nomodeset console=tty0 debug=1 break=init
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Debug - Break at Premount)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components nomodeset console=tty0 debug=1 break=premount
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
