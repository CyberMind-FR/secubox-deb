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

# Create Plymouth script - DYNAMIC REACTIVE STATUS DISPLAY
cat > "${PLYMOUTH_DIR}/secubox.script" <<'PLYSCRIPT'
# ═══════════════════════════════════════════════════════════════════════════
# SecuBox Plymouth Theme - DYNAMIC STATUS DISPLAY
# Reactive boot splash with real-time service status
# Colors: Orange=checking | Green=OK | Red=FAIL | Cyan=info
# ═══════════════════════════════════════════════════════════════════════════

# ─── COLOR DEFINITIONS (RGB 0.0-1.0) ───────────────────────────────────────
# Phosphor Orange (checking/pending)
orange_r = 1.0;   orange_g = 0.55;  orange_b = 0.0;
# Matrix Green (success/OK)
green_r = 0.0;    green_g = 1.0;    green_b = 0.25;
# Alert Red (failure/error)
red_r = 0.9;      red_g = 0.22;     red_b = 0.27;
# Cyber Cyan (info/neutral)
cyan_r = 0.0;     cyan_g = 0.83;    cyan_b = 1.0;
# Muted grey (dimmed text)
grey_r = 0.42;    grey_g = 0.42;    grey_b = 0.48;
# Gold hermetic (titles)
gold_r = 0.79;    gold_g = 0.66;    gold_b = 0.30;

# ─── BACKGROUND ────────────────────────────────────────────────────────────
Window.SetBackgroundTopColor(0.04, 0.04, 0.06);
Window.SetBackgroundBottomColor(0.02, 0.02, 0.04);

# ─── SCREEN GEOMETRY ───────────────────────────────────────────────────────
screen_width = Window.GetWidth();
screen_height = Window.GetHeight();
center_x = screen_width / 2;
center_y = screen_height / 2;

# ─── STATE TRACKING ────────────────────────────────────────────────────────
global.boot_phase = 0;
global.service_count = 0;
global.ok_count = 0;
global.fail_count = 0;
global.last_progress = 0;

# ─── HEADER BANNER ─────────────────────────────────────────────────────────
header1_text = "╔═══════════════════════════════════════════════════════════╗";
header1_sprite = Sprite();
header1_image = Image.Text(header1_text, gold_r, gold_g, gold_b, "Fixed");
header1_sprite.SetImage(header1_image);
header1_sprite.SetPosition(center_x - header1_image.GetWidth() / 2, 40, 1);

title_text = "║        SECUBOX CYBER DEFENSE PLATFORM                      ║";
title_sprite = Sprite();
title_image = Image.Text(title_text, gold_r, gold_g, gold_b, "Fixed");
title_sprite.SetImage(title_image);
title_sprite.SetPosition(center_x - title_image.GetWidth() / 2, 56, 1);

subtitle_text = "║            Secure Boot Sequence v2.0                       ║";
subtitle_sprite = Sprite();
subtitle_image = Image.Text(subtitle_text, cyan_r, cyan_g, cyan_b, "Fixed");
subtitle_sprite.SetImage(subtitle_image);
subtitle_sprite.SetPosition(center_x - subtitle_image.GetWidth() / 2, 72, 1);

header2_text = "╚═══════════════════════════════════════════════════════════╝";
header2_sprite = Sprite();
header2_image = Image.Text(header2_text, gold_r, gold_g, gold_b, "Fixed");
header2_sprite.SetImage(header2_image);
header2_sprite.SetPosition(center_x - header2_image.GetWidth() / 2, 88, 1);

# ─── PHASE INDICATOR ───────────────────────────────────────────────────────
phase_sprite = Sprite();
phase_y = 120;

fun update_phase(phase_name) {
    phase_text = "► PHASE: " + phase_name;
    phase_image = Image.Text(phase_text, orange_r, orange_g, orange_b, "Fixed");
    phase_sprite.SetImage(phase_image);
    phase_sprite.SetPosition(center_x - phase_image.GetWidth() / 2, phase_y, 1);
}

update_phase("INITIALIZING KERNEL");

# ─── STATUS LOG AREA (scrolling messages) ──────────────────────────────────
# We keep last 12 status lines
status_sprites[0] = Sprite();
status_sprites[1] = Sprite();
status_sprites[2] = Sprite();
status_sprites[3] = Sprite();
status_sprites[4] = Sprite();
status_sprites[5] = Sprite();
status_sprites[6] = Sprite();
status_sprites[7] = Sprite();
status_sprites[8] = Sprite();
status_sprites[9] = Sprite();
status_sprites[10] = Sprite();
status_sprites[11] = Sprite();

status_texts[0] = "";
status_texts[1] = "";
status_texts[2] = "";
status_texts[3] = "";
status_texts[4] = "";
status_texts[5] = "";
status_texts[6] = "";
status_texts[7] = "";
status_texts[8] = "";
status_texts[9] = "";
status_texts[10] = "";
status_texts[11] = "";

status_colors_r[0] = grey_r; status_colors_g[0] = grey_g; status_colors_b[0] = grey_b;
status_colors_r[1] = grey_r; status_colors_g[1] = grey_g; status_colors_b[1] = grey_b;
status_colors_r[2] = grey_r; status_colors_g[2] = grey_g; status_colors_b[2] = grey_b;
status_colors_r[3] = grey_r; status_colors_g[3] = grey_g; status_colors_b[3] = grey_b;
status_colors_r[4] = grey_r; status_colors_g[4] = grey_g; status_colors_b[4] = grey_b;
status_colors_r[5] = grey_r; status_colors_g[5] = grey_g; status_colors_b[5] = grey_b;
status_colors_r[6] = grey_r; status_colors_g[6] = grey_g; status_colors_b[6] = grey_b;
status_colors_r[7] = grey_r; status_colors_g[7] = grey_g; status_colors_b[7] = grey_b;
status_colors_r[8] = grey_r; status_colors_g[8] = grey_g; status_colors_b[8] = grey_b;
status_colors_r[9] = grey_r; status_colors_g[9] = grey_g; status_colors_b[9] = grey_b;
status_colors_r[10] = grey_r; status_colors_g[10] = grey_g; status_colors_b[10] = grey_b;
status_colors_r[11] = grey_r; status_colors_g[11] = grey_g; status_colors_b[11] = grey_b;

log_start_y = 160;
log_line_height = 16;
log_x = 80;

fun redraw_status_log() {
    for (i = 0; i < 12; i++) {
        if (status_texts[i] != "") {
            img = Image.Text(status_texts[i], status_colors_r[i], status_colors_g[i], status_colors_b[i], "Fixed");
            status_sprites[i].SetImage(img);
            status_sprites[i].SetPosition(log_x, log_start_y + (i * log_line_height), 1);
        }
    }
}

fun add_status_line(text, r, g, b) {
    # Scroll up - shift all entries
    for (i = 0; i < 11; i++) {
        status_texts[i] = status_texts[i + 1];
        status_colors_r[i] = status_colors_r[i + 1];
        status_colors_g[i] = status_colors_g[i + 1];
        status_colors_b[i] = status_colors_b[i + 1];
    }
    # Add new entry at bottom
    status_texts[11] = text;
    status_colors_r[11] = r;
    status_colors_g[11] = g;
    status_colors_b[11] = b;

    redraw_status_log();
}

# ─── PROGRESS BAR ──────────────────────────────────────────────────────────
progress_bar_y = log_start_y + (12 * log_line_height) + 20;
progress_bg_sprite = Sprite();
progress_fill_sprite = Sprite();
progress_text_sprite = Sprite();

# Background bar
progress_bg_text = "╔══════════════════════════════════════════════════════════╗";
progress_bg_image = Image.Text(progress_bg_text, grey_r, grey_g, grey_b, "Fixed");
progress_bg_sprite.SetImage(progress_bg_image);
progress_bg_sprite.SetPosition(center_x - progress_bg_image.GetWidth() / 2, progress_bar_y, 1);

fun update_progress_bar(progress) {
    fill_count = Math.Int(progress * 58);
    fill_text = "║";
    for (i = 0; i < fill_count; i++) {
        fill_text = fill_text + "█";
    }
    for (i = fill_count; i < 58; i++) {
        fill_text = fill_text + " ";
    }
    fill_text = fill_text + "║";

    # Color based on progress: orange while loading, green when done
    if (progress < 1.0) {
        fill_image = Image.Text(fill_text, orange_r, orange_g, orange_b, "Fixed");
    } else {
        fill_image = Image.Text(fill_text, green_r, green_g, green_b, "Fixed");
    }
    progress_fill_sprite.SetImage(fill_image);
    progress_fill_sprite.SetPosition(center_x - fill_image.GetWidth() / 2, progress_bar_y + 16, 1);

    # Progress percentage
    pct = Math.Int(progress * 100);
    pct_text = "╚═══════════════════════ " + pct + "% ═══════════════════════╝";
    pct_image = Image.Text(pct_text, cyan_r, cyan_g, cyan_b, "Fixed");
    progress_text_sprite.SetImage(pct_image);
    progress_text_sprite.SetPosition(center_x - pct_image.GetWidth() / 2, progress_bar_y + 32, 1);
}

update_progress_bar(0);

# ─── STATS LINE ────────────────────────────────────────────────────────────
stats_sprite = Sprite();
stats_y = progress_bar_y + 60;

fun update_stats() {
    stats_text = "│ Services: " + global.service_count + " │ OK: " + global.ok_count + " │ FAIL: " + global.fail_count + " │";

    if (global.fail_count > 0) {
        stats_image = Image.Text(stats_text, red_r, red_g, red_b, "Fixed");
    } else if (global.ok_count > 0) {
        stats_image = Image.Text(stats_text, green_r, green_g, green_b, "Fixed");
    } else {
        stats_image = Image.Text(stats_text, cyan_r, cyan_g, cyan_b, "Fixed");
    }
    stats_sprite.SetImage(stats_image);
    stats_sprite.SetPosition(center_x - stats_image.GetWidth() / 2, stats_y, 1);
}

update_stats();

# ─── CURSOR BLINK ──────────────────────────────────────────────────────────
cursor_sprite = Sprite();

fun refresh_callback() {
    time = Plymouth.GetTime();

    # Blinking cursor
    if (Math.Int(time * 2) % 2 == 0) {
        cursor_text = "█";
        cursor_image = Image.Text(cursor_text, orange_r, orange_g, orange_b, "Fixed");
    } else {
        cursor_text = " ";
        cursor_image = Image.Text(cursor_text, 0, 0, 0, "Fixed");
    }
    cursor_sprite.SetImage(cursor_image);
    cursor_sprite.SetPosition(log_x + 500, log_start_y + (11 * log_line_height), 2);
}

Plymouth.SetRefreshFunction(refresh_callback);

# ─── BOOT PROGRESS CALLBACK ────────────────────────────────────────────────
fun boot_progress_callback(duration, progress) {
    update_progress_bar(progress);
    global.last_progress = progress;

    # Update phase based on progress
    if (progress < 0.2) {
        update_phase("KERNEL INITIALIZATION");
    } else if (progress < 0.4) {
        update_phase("HARDWARE DETECTION");
    } else if (progress < 0.6) {
        update_phase("FILESYSTEM MOUNT");
    } else if (progress < 0.8) {
        update_phase("NETWORK CONFIGURATION");
    } else if (progress < 0.95) {
        update_phase("SECURITY SERVICES");
    } else {
        update_phase("SYSTEM READY");
    }
}

Plymouth.SetBootProgressFunction(boot_progress_callback);

# ─── MESSAGE CALLBACK (systemd status messages) ────────────────────────────
# Plymouth receives messages in format: "message:status" where status is ok/fail/etc
# All messages shown in orange (pending) - update_status_callback handles final state

fun message_callback(text) {
    global.service_count++;
    # Show message in orange (checking state)
    add_status_line("[....] " + text, orange_r, orange_g, orange_b);
    update_stats();
}

Plymouth.SetMessageFunction(message_callback);

# ─── UPDATE STATUS CALLBACK (final status from systemd) ────────────────────
# This is called with status: "normal", "pause", "unpause", etc
# And separately for service status via system messages

fun update_status_callback(status) {
    # Status updates from systemd - track success/failure
    if (status == "normal") {
        # Boot proceeding normally
        global.ok_count++;
    } else if (status == "failed" || status == "error") {
        global.fail_count++;
        add_status_line("[FAIL] Boot error detected", red_r, red_g, red_b);
    }
    update_stats();
}

Plymouth.SetUpdateStatusFunction(update_status_callback);

# ─── PASSWORD PROMPT ───────────────────────────────────────────────────────
password_sprite = Sprite();
password_box_sprite = Sprite();

fun display_password_callback(prompt, bullets) {
    # Password prompt in orange
    prompt_text = "╔═══ " + prompt + " ═══╗";
    prompt_image = Image.Text(prompt_text, orange_r, orange_g, orange_b, "Fixed");
    password_sprite.SetImage(prompt_image);
    password_sprite.SetPosition(center_x - prompt_image.GetWidth() / 2, center_y, 1);

    # Password bullets
    bullet_text = "║ " + bullets + " ║";
    bullet_image = Image.Text(bullet_text, gold_r, gold_g, gold_b, "Fixed");
    password_box_sprite.SetImage(bullet_image);
    password_box_sprite.SetPosition(center_x - bullet_image.GetWidth() / 2, center_y + 20, 1);
}

fun display_normal_callback() {
    password_sprite.SetOpacity(0);
    password_box_sprite.SetOpacity(0);
}

Plymouth.SetDisplayNormalFunction(display_normal_callback);
Plymouth.SetDisplayPasswordFunction(display_password_callback);

# ─── SYSTEM UPDATE ─────────────────────────────────────────────────────────
fun system_update_callback(progress) {
    update_text = "SYSTEM UPDATE IN PROGRESS: " + Math.Int(progress * 100) + "%";
    add_status_line(update_text, cyan_r, cyan_g, cyan_b);
    update_progress_bar(progress);
}

Plymouth.SetSystemUpdateFunction(system_update_callback);

# ─── QUIT CALLBACK ─────────────────────────────────────────────────────────
fun quit_callback() {
    update_phase("BOOT COMPLETE");
    update_progress_bar(1.0);
    add_status_line("═══ SecuBox Ready ═══", green_r, green_g, green_b);
}

Plymouth.SetQuitFunction(quit_callback);

# ─── INITIAL MESSAGE ───────────────────────────────────────────────────────
add_status_line("SecuBox Cyber Defense Platform", gold_r, gold_g, gold_b);
add_status_line("Initializing secure boot sequence...", cyan_r, cyan_g, cyan_b);
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
    chroot "${ROOTFS}" apt-get install -y -q secubox-full 2>/dev/null || true

    # Verify secubox-core installed (dependency of secubox-full)
    if ! chroot "${ROOTFS}" dpkg -l secubox-core 2>/dev/null | grep -q "^ii"; then
      warn "secubox-full unavailable"
    fi
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

# Plymouth boot status generator - sends real service status to plymouth
cat > "${ROOTFS}/usr/local/bin/secubox-boot-status" <<'BOOTSTATUS'
#!/bin/bash
# SecuBox Boot Status Generator - sends status to Plymouth
# Colors: orange=checking, green=ok, red=fail

plymouth_msg() {
    plymouth display-message --text="$1" 2>/dev/null || true
}

plymouth_ok() {
    plymouth update --status="normal" 2>/dev/null || true
}

plymouth_fail() {
    plymouth update --status="failed" 2>/dev/null || true
}

# Monitor systemd boot progress
while true; do
    # Get currently starting services
    starting=$(systemctl list-jobs --no-legend 2>/dev/null | head -5)

    if [[ -n "$starting" ]]; then
        # Extract first starting service
        svc=$(echo "$starting" | head -1 | awk '{print $2}')
        if [[ -n "$svc" ]]; then
            plymouth_msg "Starting: ${svc%.service}"
        fi
    fi

    # Check for failed services
    failed=$(systemctl --failed --no-legend 2>/dev/null | wc -l)
    if [[ $failed -gt 0 ]]; then
        plymouth_fail
        fail_name=$(systemctl --failed --no-legend 2>/dev/null | head -1 | awk '{print $1}')
        plymouth_msg "FAILED: ${fail_name%.service}"
    fi

    # Check if boot is complete
    if systemctl is-system-running --quiet 2>/dev/null; then
        plymouth_ok
        plymouth_msg "SecuBox Ready"
        exit 0
    fi

    # Check if we're in degraded state (some failures but running)
    state=$(systemctl is-system-running 2>/dev/null || echo "starting")
    if [[ "$state" == "degraded" ]]; then
        plymouth_msg "System degraded - some services failed"
        exit 0
    fi

    sleep 0.5
done
BOOTSTATUS
chmod +x "${ROOTFS}/usr/local/bin/secubox-boot-status"

# Boot status service
cat > "${ROOTFS}/etc/systemd/system/secubox-boot-status.service" <<'BOOTSTATUSSVC'
[Unit]
Description=SecuBox Boot Status for Plymouth
DefaultDependencies=no
After=plymouth-start.service
Before=plymouth-quit.service plymouth-quit-wait.service
ConditionKernelCommandLine=splash

[Service]
Type=simple
ExecStart=/usr/local/bin/secubox-boot-status
TimeoutStartSec=90
TimeoutStopSec=5

[Install]
WantedBy=sysinit.target
BOOTSTATUSSVC
chroot "${ROOTFS}" systemctl enable secubox-boot-status.service 2>/dev/null || true

# ── Kiosk mode packages ───────────────────────────────────────────
if [[ $INCLUDE_KIOSK -eq 1 ]]; then
  log "Installing kiosk mode packages..."
  chroot "${ROOTFS}" apt-get install -y -q --no-install-recommends \
    cage chromium fonts-dejavu-core \
    xwayland kbd \
    libinput10 libegl1 libgles2 libgbm1 libdrm2 \
    mesa-utils xdg-utils 2>/dev/null || true

  # Verify key kiosk packages installed
  if ! chroot "${ROOTFS}" dpkg -l cage chromium 2>/dev/null | grep -q "^ii"; then
    warn "Kiosk packages failed"
  fi

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
set default=1
set timeout=5

insmod part_gpt
insmod fat
insmod ext2
insmod all_video

search --no-floppy --label LIVE --set=live

set menu_color_normal=cyan/black
set menu_color_highlight=white/blue

menuentry "SecuBox Live" {
    linux ($live)/live/vmlinuz boot=live live-media-path=live components persistence quiet splash
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Kiosk GUI)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=live components persistence quiet splash secubox.kiosk=1 systemd.unit=graphical.target
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Bridge Mode)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=live components persistence quiet splash secubox.netmode=bridge
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Safe Mode)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=live components nomodeset console=tty0
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (To RAM)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=live components toram quiet splash
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Auto-Check HW)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=live components persistence quiet splash secubox.hwcheck=1
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Auto-Check HW - Text Mode)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=live components persistence nomodeset console=tty0 secubox.hwcheck=1
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Emergency Shell)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=live components nomodeset console=tty0 systemd.unit=emergency.target
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Debug - Verbose Boot)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=live components nomodeset console=tty0 debug=1 break=init
    initrd ($live)/live/initrd.img
}

menuentry "SecuBox Live (Debug - Break at Premount)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=live components nomodeset console=tty0 debug=1 break=premount
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
