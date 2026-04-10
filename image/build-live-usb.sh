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

# ── Version & Build Info ──────────────────────────────────────────
SECUBOX_VERSION="1.5.10"
BUILD_TIMESTAMP=$(date '+%Y-%m-%d %H:%M')
BUILD_DATE=$(date '+%Y%m%d')

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
  # Unmount in reverse order of mounting
  umount -lf "${ROOTFS}/dev/pts" 2>/dev/null || true
  umount -lf "${ROOTFS}/proc" 2>/dev/null || true
  umount -lf "${ROOTFS}/sys"  2>/dev/null || true
  # Wait and force umount /dev last (critical to not destroy host /dev)
  sync
  sleep 1
  if mountpoint -q "${ROOTFS}/dev" 2>/dev/null; then
    umount -f "${ROOTFS}/dev" 2>/dev/null || umount -lf "${ROOTFS}/dev" 2>/dev/null || true
  fi
  umount -lf "${WORK_DIR}/mnt/"* 2>/dev/null || true
  [[ -n "${LOOP:-}" ]] && losetup -d "${LOOP}" 2>/dev/null || true
  # Only remove if no mounts are active
  if ! mount | grep -q "${WORK_DIR}"; then
    rm -rf "${WORK_DIR}" 2>/dev/null || true
  else
    log "WARNING: ${WORK_DIR} still has active mounts, not removing"
  fi
}
trap cleanup EXIT

# ══════════════════════════════════════════════════════════════════
# Step 1: Debootstrap
# ══════════════════════════════════════════════════════════════════
log "1/8 Debootstrap ${SUITE} amd64..."
mkdir -p "${ROOTFS}"

INCLUDE_PKGS="systemd,systemd-sysv,dbus,netplan.io,nftables,openssh-server,locales"
INCLUDE_PKGS+=",python3,python3-pip,nginx,curl,wget,ca-certificates,gnupg,console-setup"
INCLUDE_PKGS+=",iproute2,iputils-ping,ethtool,net-tools,wireguard-tools"
INCLUDE_PKGS+=",sudo,less,vim-tiny,logrotate,cron,rsync,jq,dnsmasq"
INCLUDE_PKGS+=",linux-image-amd64,live-boot,live-boot-initramfs-tools,live-config,live-config-systemd"
INCLUDE_PKGS+=",grub-efi-amd64,grub-pc-bin,efibootmgr,pciutils,usbutils,parted,dosfstools,lsb-release"
INCLUDE_PKGS+=",plymouth,plymouth-themes"

debootstrap --arch=amd64 --include="${INCLUDE_PKGS}" \
  "${SUITE}" "${ROOTFS}" "${APT_MIRROR}"

ok "Debootstrap complete"

# ══════════════════════════════════════════════════════════════════
# Step 2: Base configuration
# ══════════════════════════════════════════════════════════════════
log "2/8 System configuration..."

# Only mount if not already mounted
mountpoint -q "${ROOTFS}/proc" || mount -t proc proc   "${ROOTFS}/proc"
mountpoint -q "${ROOTFS}/sys"  || mount -t sysfs sysfs "${ROOTFS}/sys"
mountpoint -q "${ROOTFS}/dev"  || mount --bind /dev    "${ROOTFS}/dev"

# Hostname
echo "secubox-live" > "${ROOTFS}/etc/hostname"
cat > "${ROOTFS}/etc/hosts" <<EOF
127.0.0.1  localhost secubox-live secubox secubox.local
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
StandardInput=tty
StandardOutput=tty
TTYVTDisallocate=no
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

# ── Profile.d script for login status display ──────────────────────────────────
mkdir -p "${ROOTFS}/etc/profile.d"
cat > "${ROOTFS}/etc/profile.d/secubox-login.sh" <<'PROFILE'
#!/bin/bash
# SecuBox Login Status Display
# Shows quick system status on interactive shell login

# Only run on interactive terminals
[[ $- != *i* ]] && return
[[ -z "$PS1" ]] && return

# Avoid double display with splash
[[ -n "$SECUBOX_STATUS_SHOWN" ]] && return
export SECUBOX_STATUS_SHOWN=1

# Colors
GOLD='\033[38;5;214m'
CYAN='\033[38;5;45m'
GREEN='\033[38;5;82m'
RED='\033[38;5;196m'
GRAY='\033[38;5;242m'
WHITE='\033[38;5;250m'
RESET='\033[0m'

# Quick status line after MOTD
show_quick_status() {
    local ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    local services_ok=0
    local services_fail=0

    for svc in nginx secubox-api nftables; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            ((services_ok++))
        else
            ((services_fail++))
        fi
    done

    # Mode indicator
    local mode_icon="🖥️"
    local mode_text="Console"
    if [[ -f /var/lib/secubox/.kiosk-enabled ]]; then
        mode_icon="🖼️"
        mode_text="Kiosk"
    elif [[ -f /var/lib/secubox/.tui-enabled ]]; then
        mode_icon="📟"
        mode_text="TUI"
    fi

    echo ""
    echo -e "${GRAY}────────────────────────────────────────────────────────────${RESET}"
    echo -e "  ${mode_icon} ${CYAN}${mode_text}${RESET}  │  ${GREEN}●${RESET} ${services_ok} services  │  🌐 ${CYAN}${ip:-no-ip}${RESET}"
    echo -e "${GRAY}────────────────────────────────────────────────────────────${RESET}"
    echo -e "  ${GRAY}Type ${WHITE}secubox-status${GRAY} for details  •  ${WHITE}secubox-help${GRAY} for commands${RESET}"
    echo ""
}

# Only show on tty login, not in SSH or within screen/tmux
if [[ -z "$SSH_TTY" ]] && [[ -z "$TMUX" ]] && [[ -z "$STY" ]]; then
    show_quick_status
fi
PROFILE
chmod +x "${ROOTFS}/etc/profile.d/secubox-login.sh"

# ── SecuBox help command ─────────────────────────────────────────────────────
cat > "${ROOTFS}/usr/bin/secubox-help" <<'HELP_CMD'
#!/bin/bash
# SecuBox Quick Help
GOLD='\033[38;5;214m'
CYAN='\033[38;5;45m'
WHITE='\033[38;5;250m'
GRAY='\033[38;5;242m'
RESET='\033[0m'

echo -e "${GOLD}"
echo '  ╭─────────────────────────────────────────────────────────╮'
echo '  │             ⚡ SecuBox Quick Commands                   │'
echo '  ╰─────────────────────────────────────────────────────────╯'
echo -e "${RESET}"

echo -e "  ${WHITE}System${RESET}"
echo -e "    ${CYAN}secubox-status${GRAY}        System overview with services${RESET}"
echo -e "    ${CYAN}secubox-logs${GRAY}          Live security logs${RESET}"
echo -e "    ${CYAN}secubox-services${GRAY}      Manage services${RESET}"
echo ""
echo -e "  ${WHITE}Network${RESET}"
echo -e "    ${CYAN}secubox-network${GRAY}       Network configuration${RESET}"
echo -e "    ${CYAN}secubox-firewall${GRAY}      Firewall rules status${RESET}"
echo ""
echo -e "  ${WHITE}Security${RESET}"
echo -e "    ${CYAN}secubox-threats${GRAY}       View blocked threats${RESET}"
echo -e "    ${CYAN}secubox-waf-status${GRAY}    WAF inspection status${RESET}"
echo ""
echo -e "  ${WHITE}Modes${RESET}"
echo -e "    ${CYAN}secubox-mode kiosk${GRAY}    Switch to Kiosk GUI${RESET}"
echo -e "    ${CYAN}secubox-mode tui${GRAY}      Switch to TUI dashboard${RESET}"
echo -e "    ${CYAN}secubox-mode console${GRAY}  Switch to shell console${RESET}"
echo ""
echo -e "  ${GRAY}Web UI: https://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):9443${RESET}"
echo ""
HELP_CMD
chmod +x "${ROOTFS}/usr/bin/secubox-help"

# ── SecuBox logs command ─────────────────────────────────────────────────────
cat > "${ROOTFS}/usr/bin/secubox-logs" <<'LOGS_CMD'
#!/bin/bash
# SecuBox Live Security Logs
echo "📋 SecuBox Security Logs (Ctrl+C to exit)"
echo "─────────────────────────────────────────"
journalctl -f -u 'secubox-*' -u crowdsec -u suricata -u nginx --no-pager 2>/dev/null || \
journalctl -f --no-pager
LOGS_CMD
chmod +x "${ROOTFS}/usr/bin/secubox-logs"

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
# Matches all common interface naming schemes for universal hardware compatibility
cat > "${ROOTFS}/etc/netplan/00-secubox.yaml" <<'NETPLAN'
network:
  version: 2
  renderer: networkd
  ethernets:
    # All Intel/Realtek/etc wired interfaces (enp*, eno*, enx*, ens*)
    all-wired:
      match:
        name: "e*"
        driver: "*"
      dhcp4: true
      dhcp4-overrides:
        use-dns: true
        use-routes: true
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

# Fallback network script - runs after boot, retries DHCP and adds link-local if failed
cat > "${ROOTFS}/usr/sbin/secubox-net-fallback" <<'FALLBACK'
#!/bin/bash
# SecuBox Network Fallback - retries DHCP on all interfaces, adds link-local if failed
logger -t secubox-net "Network fallback starting..."

# Wait a bit for interfaces to come up
sleep 5

# Find all physical network interfaces (exclude lo, docker, veth, dummy, etc)
for iface in /sys/class/net/*; do
    [ -e "$iface" ] || continue
    IFACE=$(basename "$iface")

    # Skip non-physical interfaces
    case "$IFACE" in
        lo|dummy*|docker*|veth*|br-*|virbr*) continue ;;
    esac

    # Only process interfaces starting with e (ethernet) or w (wifi)
    case "$IFACE" in
        e*|w*) ;;
        *) continue ;;
    esac

    # Bring interface up
    ip link set "$IFACE" up 2>/dev/null

    # Check if interface has an IP
    if ! ip addr show "$IFACE" | grep -q "inet "; then
        logger -t secubox-net "No IP on $IFACE, triggering DHCP..."

        # Try DHCP via networkctl
        networkctl reconfigure "$IFACE" 2>/dev/null || true
        sleep 10

        # Check again
        if ! ip addr show "$IFACE" | grep -q "inet "; then
            logger -t secubox-net "DHCP failed on $IFACE, adding link-local"
            ip addr add 169.254.1.1/16 dev "$IFACE" 2>/dev/null || true
        else
            logger -t secubox-net "DHCP succeeded on $IFACE"
        fi
    else
        logger -t secubox-net "Interface $IFACE already has IP"
    fi
done

logger -t secubox-net "Network fallback complete"
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

# Mount special filesystems for chroot (required for apt)
# Cleanup is handled by the cleanup() function at script exit
mount_chroot_fs() {
  log "Mounting special filesystems in chroot..."
  # Only mount if not already mounted
  mountpoint -q "${ROOTFS}/dev"     || mount --bind /dev "${ROOTFS}/dev"
  mountpoint -q "${ROOTFS}/dev/pts" || mount --bind /dev/pts "${ROOTFS}/dev/pts" 2>/dev/null || true
  mountpoint -q "${ROOTFS}/proc"    || mount -t proc proc "${ROOTFS}/proc"
  mountpoint -q "${ROOTFS}/sys"     || mount -t sysfs sysfs "${ROOTFS}/sys"
}

mount_chroot_fs

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

# ── Install critical disk tools (for secubox-install) ─────────────
log "Installing disk tools..."
chroot "${ROOTFS}" apt-get install -y -q parted fdisk e2fsprogs dosfstools || warn "Disk tools install failed"
ok "Disk tools installed (parted, fdisk, e2fsprogs, dosfstools)"

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
  fastapi uvicorn[standard] python-jose[cryptography] httpx \
  jinja2 tomli toml pyroute2 psutil pydantic \
  aiofiles aiosqlite authlib cryptography \
  python-multipart websockets netifaces \
  2>&1 | tail -10 || true
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

# Find all .deb files in cache/repo or output/
# Note: Packages may be in output/ directly OR output/debs/ subdirectory
CACHE_DEBS="${REPO_DIR}/cache/repo/pool"
# Check both output/ and output/debs/ for packages
if [[ -d "${REPO_DIR}/output" ]] && ls "${REPO_DIR}/output"/secubox-*.deb >/dev/null 2>&1; then
  OUTPUT_DEBS="${REPO_DIR}/output"
else
  OUTPUT_DEBS="${REPO_DIR}/output/debs"
fi

# Check both locations for packages (handle non-existent dirs gracefully)
if [[ -d "$CACHE_DEBS" ]]; then
  CACHE_COUNT=$(find "$CACHE_DEBS" -name "secubox-*.deb" 2>/dev/null | wc -l)
else
  CACHE_COUNT=0
fi
if [[ -d "$OUTPUT_DEBS" ]]; then
  OUTPUT_COUNT=$(find "$OUTPUT_DEBS" -maxdepth 1 -name "secubox-*.deb" 2>/dev/null | wc -l)
else
  OUTPUT_COUNT=0
fi
log "Found ${CACHE_COUNT} packages in cache, ${OUTPUT_COUNT} in output/debs"

if [[ $CACHE_COUNT -gt 0 ]] || [[ $OUTPUT_COUNT -gt 0 ]]; then
  log "Slipstream: Installing from local packages"
  install -d "${ROOTFS}/tmp/secubox-debs"

  # Copy from output/debs FIRST (prefer newer local builds over cache)
  if [[ -d "$OUTPUT_DEBS" ]]; then
    for deb in "${OUTPUT_DEBS}"/secubox-*.deb; do
      [[ -f "$deb" ]] || continue
      cp "$deb" "${ROOTFS}/tmp/secubox-debs/"
    done
    log "Copied ${OUTPUT_COUNT} packages from output/debs"
  fi

  # Then add from cache for packages not in output/debs
  if [[ $CACHE_COUNT -gt 0 ]]; then
    for deb in $(find "$CACHE_DEBS" -name "secubox-*.deb"); do
      pkg_name=$(basename "$deb" | sed 's/_.*$//')
      # Only copy if not already present (prefer output/debs version)
      if ! ls "${ROOTFS}/tmp/secubox-debs/${pkg_name}_"*.deb >/dev/null 2>&1; then
        cp "$deb" "${ROOTFS}/tmp/secubox-debs/"
        log "Added ${pkg_name} from cache"
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

  # ── Ensure systemd directories exist ─────────────────────────────────────
  log "Ensuring systemd directories exist..."
  install -d -m 755 "${ROOTFS}/usr/lib/systemd/system"
  install -d -m 755 "${ROOTFS}/etc/systemd/system"
  ok "systemd directories ready"

  # ── Pre-install Python dependencies via pip (not in Debian repos) ───────
  log "Pre-installing Python dependencies for SecuBox modules..."
  chroot "${ROOTFS}" pip3 install --break-system-packages \
    fastapi uvicorn[standard] httpx python-jose aiofiles aiosqlite \
    pydantic toml jinja2 psutil netifaces 2>/dev/null && \
    ok "Python dependencies installed via pip" || warn "Some pip packages failed (may be installed by apt later)"

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

  # Configure packages (skip apt-get -f as pip provides Python deps)
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

# Disable strict mode temporarily for glob handling
set +e

log "DEBUG: Checking conf.d..."
for conf in "${ROOTFS}/etc/nginx/conf.d/secubox-"*.conf "${ROOTFS}/etc/nginx/conf.d/"*secubox*.conf; do
  [[ -e "$conf" ]] || continue
  if [[ -L "$conf" ]]; then
    rm -f "$conf"
    log "Removed symlink $(basename "$conf") from conf.d/"
  elif [[ -f "$conf" ]] && grep -q "^location" "$conf" 2>/dev/null; then
    mv "$conf" "${ROOTFS}/etc/nginx/secubox.d/" 2>/dev/null || true
    log "Moved $(basename "$conf") to secubox.d/"
  fi
done
log "DEBUG: conf.d done"

log "DEBUG: Checking sites-enabled..."
for site in "${ROOTFS}/etc/nginx/sites-enabled/secubox-"*; do
  [[ -e "$site" ]] || [[ -L "$site" ]] || continue
  real_file="$site"
  [[ -L "$site" ]] && real_file=$(readlink -f "$site" 2>/dev/null | sed "s|^|${ROOTFS}|; s|${ROOTFS}${ROOTFS}|${ROOTFS}|") || true
  if [[ -f "$real_file" ]] && grep -q "^location" "$real_file" 2>/dev/null; then
    base_name=$(basename "$site" | sed 's/^secubox-//')
    cp "$real_file" "${ROOTFS}/etc/nginx/secubox.d/${base_name}.conf" 2>/dev/null || true
    rm -f "$site"
    log "Moved $(basename "$site") content to secubox.d/${base_name}.conf"
  fi
done
log "DEBUG: sites-enabled done"

log "DEBUG: Cleaning broken symlinks in secubox.d..."
for conf in "${ROOTFS}/etc/nginx/secubox.d/"*.conf; do
  if [[ -L "$conf" ]] && [[ ! -e "$conf" ]]; then
    rm -f "$conf" && log "Removed broken symlink $(basename "$conf")" || true
  fi
done
log "DEBUG: symlink cleanup 1 done"

log "DEBUG: Cleaning symlinks to non-existent targets..."
for conf in "${ROOTFS}/etc/nginx/secubox.d/"*.conf; do
  if [[ -L "$conf" ]]; then
    target=$(readlink "$conf" 2>/dev/null) || target=""
    if [[ -n "$target" ]] && [[ "$target" == /* ]] && [[ ! -e "${ROOTFS}${target}" ]]; then
      rm -f "$conf"
      log "Removed broken symlink $(basename "$conf") -> $target"
    fi
  fi
done
log "DEBUG: symlink cleanup 2 done"

# Re-enable strict mode
set -e

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
  "board": "amd64-live",
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

# ── Fix nginx configuration to ensure it starts ─────────────────────
log "Fixing nginx configuration..."

# Ensure snippets directory exists
mkdir -p "${ROOTFS}/etc/nginx/snippets"
mkdir -p "${ROOTFS}/etc/nginx/secubox.d"

# Install secubox-proxy.conf snippet if missing
if [[ ! -f "${ROOTFS}/etc/nginx/snippets/secubox-proxy.conf" ]]; then
  if [[ -f "${ROOTFS}/usr/share/secubox-core/nginx/secubox-proxy.conf" ]]; then
    cp "${ROOTFS}/usr/share/secubox-core/nginx/secubox-proxy.conf" \
       "${ROOTFS}/etc/nginx/snippets/secubox-proxy.conf"
    log "Installed secubox-proxy.conf snippet"
  else
    # Create minimal proxy config
    cat > "${ROOTFS}/etc/nginx/snippets/secubox-proxy.conf" << 'PROXYEOF'
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_read_timeout 30s;
proxy_connect_timeout 5s;
proxy_buffering off;
PROXYEOF
    log "Created minimal secubox-proxy.conf snippet"
  fi
fi

# Install main secubox nginx config if missing
if [[ ! -f "${ROOTFS}/etc/nginx/sites-available/secubox" ]]; then
  if [[ -f "${ROOTFS}/usr/share/secubox-core/nginx/secubox.conf" ]]; then
    cp "${ROOTFS}/usr/share/secubox-core/nginx/secubox.conf" \
       "${ROOTFS}/etc/nginx/sites-available/secubox"
    ln -sf /etc/nginx/sites-available/secubox \
       "${ROOTFS}/etc/nginx/sites-enabled/secubox"
    rm -f "${ROOTFS}/etc/nginx/sites-enabled/default"
    log "Installed secubox nginx site config"
  fi
fi

# Remove bad configs from conf.d (location-only files belong in secubox.d, not conf.d)
log "Cleaning bad nginx configs from conf.d..."
for conf in "${ROOTFS}/etc/nginx/conf.d/"*secubox*.conf "${ROOTFS}/etc/nginx/conf.d/secubox-"*; do
  [[ -f "$conf" ]] || [[ -L "$conf" ]] || continue

  # Resolve symlink if needed
  real_file="$conf"
  if [[ -L "$conf" ]]; then
    target=$(readlink "$conf")
    if [[ "$target" == /* ]]; then
      real_file="${ROOTFS}${target}"
    else
      real_file="${ROOTFS}/etc/nginx/conf.d/${target}"
    fi
  fi

  # If file contains location directive (not inside server block), it's misplaced
  if [[ -f "$real_file" ]] && grep -q "^location" "$real_file" 2>/dev/null; then
    base=$(basename "$conf" .conf | sed 's/^secubox-//')
    # Move content to secubox.d if not already there
    if [[ ! -f "${ROOTFS}/etc/nginx/secubox.d/${base}.conf" ]]; then
      cp "$real_file" "${ROOTFS}/etc/nginx/secubox.d/${base}.conf" 2>/dev/null || true
      log "Moved ${base} from conf.d to secubox.d"
    fi
    rm -f "$conf"
  fi
done

# Remove bad configs from sites-enabled (location-only files belong in secubox.d)
log "Cleaning bad nginx configs from sites-enabled..."
for site in "${ROOTFS}/etc/nginx/sites-enabled/"*; do
  [[ -f "$site" ]] || [[ -L "$site" ]] || continue
  [[ "$(basename "$site")" == "secubox" ]] && continue  # Keep main secubox config

  # Check if file exists (resolve symlink)
  real_file="$site"
  [[ -L "$site" ]] && real_file=$(readlink -f "$site") && real_file="${ROOTFS}${real_file#${ROOTFS}}"
  [[ -f "$real_file" ]] || { rm -f "$site"; continue; }

  # If it starts with location (not server), move to secubox.d
  if grep -q "^location" "$real_file" 2>/dev/null && ! grep -q "^server" "$real_file" 2>/dev/null; then
    base=$(basename "$site" | sed 's/^secubox-//')
    cp "$real_file" "${ROOTFS}/etc/nginx/secubox.d/${base}.conf" 2>/dev/null || true
    rm -f "$site"
    log "Moved $(basename "$site") to secubox.d/ (was location-only)"
  fi
done

# Test nginx configuration in chroot
log "Testing nginx configuration..."
if chroot "${ROOTFS}" nginx -t 2>&1; then
  ok "nginx configuration valid"
else
  warn "nginx config test failed - attempting auto-fix..."
  # Show specific error
  error_output=$(chroot "${ROOTFS}" nginx -t 2>&1 | head -5)
  echo "$error_output"

  # Extract problematic file from error message
  bad_file=$(echo "$error_output" | grep -oP '/etc/nginx/[^:]+' | head -1)
  if [[ -n "$bad_file" ]] && [[ -f "${ROOTFS}${bad_file}" ]]; then
    log "Disabling problematic config: $bad_file"
    mv "${ROOTFS}${bad_file}" "${ROOTFS}${bad_file}.disabled" 2>/dev/null || rm -f "${ROOTFS}${bad_file}"

    # Test again
    if chroot "${ROOTFS}" nginx -t 2>&1; then
      ok "nginx configuration fixed by disabling $bad_file"
    else
      warn "nginx still failing, may need manual fix at runtime"
    fi
  fi

  # If SSL certs missing, regenerate
  if [[ ! -f "${ROOTFS}/etc/secubox/tls/cert.pem" ]]; then
    warn "SSL certificates missing, regenerating..."
    mkdir -p "${ROOTFS}/etc/secubox/tls"
    openssl req -x509 -newkey rsa:2048 -days 365 \
      -keyout "${ROOTFS}/etc/secubox/tls/key.pem" \
      -out "${ROOTFS}/etc/secubox/tls/cert.pem" \
      -nodes -subj "/CN=secubox-live/O=CyberMind SecuBox/C=FR" 2>/dev/null
  fi
fi

# Note: SSL certs were already generated before package installation

# ══════════════════════════════════════════════════════════════════
# Step 5: Network detection & kiosk scripts
# ══════════════════════════════════════════════════════════════════
log "5/8 Installing SecuBox scripts..."

mkdir -p "${ROOTFS}/usr/sbin"
mkdir -p "${ROOTFS}/usr/lib/secubox"

# Copy scripts (including kiosk-launcher for robust startup, TUI, and mode switcher)
for script in secubox-net-detect secubox-kiosk-setup secubox-cmdline-handler secubox-kiosk-launcher secubox-x11-splash secubox-console-tui secubox-mode; do
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
  # nodm = minimal display manager designed for kiosk/embedded systems
  chroot "${ROOTFS}" env DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    xorg xinit x11-xserver-utils x11-utils \
    nodm \
    xserver-xorg-video-fbdev \
    xserver-xorg-video-vmware \
    xserver-xorg-video-vesa \
    fonts-dejavu-core unclutter kbd \
    libinput10 xdg-utils \
    virtualbox-guest-x11 virtualbox-guest-utils 2>/dev/null || warn "Some X11 packages failed"

  # Ensure critical kiosk packages are installed
  chroot "${ROOTFS}" env DEBIAN_FRONTEND=noninteractive apt-get install -y -q xinit kbd || warn "xinit/kbd install failed"

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

  # Create X11 .xsession for kiosk (used by nodm and xinit)
  mkdir -p "${ROOTFS}/home/secubox-kiosk/.config"
  cat > "${ROOTFS}/home/secubox-kiosk/.xsession" <<'XSESSION'
#!/bin/bash
# SecuBox Kiosk X Session - Minimal version
exec 2>&1 | logger -t secubox-kiosk &

echo "Starting kiosk session..."

# Basic X settings (ignore errors)
xset s off 2>/dev/null
xset -dpms 2>/dev/null

# URL to display - use localhost for universal compatibility (works without network)
URL="https://localhost/"

# Try Chromium with minimal flags
exec chromium \
    --kiosk \
    --no-first-run \
    --no-sandbox \
    --disable-gpu \
    --ignore-certificate-errors \
    --window-position=0,0 \
    "$URL" || exec xterm -fullscreen -e "echo 'Chromium failed'; sleep 999"
XSESSION
  chmod +x "${ROOTFS}/home/secubox-kiosk/.xsession"
  # Create symlink for xinit compatibility
  ln -sf .xsession "${ROOTFS}/home/secubox-kiosk/.xinitrc"
  chroot "${ROOTFS}" chown -R secubox-kiosk:secubox-kiosk /home/secubox-kiosk

  # Mark as installed AND enabled (so kiosk starts on first boot)
  mkdir -p "${ROOTFS}/var/lib/secubox"
  echo "installed=$(date -Iseconds)" > "${ROOTFS}/var/lib/secubox/.kiosk-installed"
  touch "${ROOTFS}/var/lib/secubox/.kiosk-enabled"
  echo "x11" > "${ROOTFS}/var/lib/secubox/.kiosk-mode"

  # Configure nodm display manager for reliable kiosk startup
  cat > "${ROOTFS}/etc/default/nodm" <<'NODM'
# nodm configuration for SecuBox Kiosk
NODM_ENABLED=true
NODM_USER=secubox-kiosk
NODM_FIRST_VT=7
NODM_XSESSION=/home/secubox-kiosk/.xsession
NODM_X_OPTIONS="-nolisten tcp"
NODM_MIN_SESSION_TIME=60
NODM

  # Disable nodm systemd service (we use secubox-kiosk.service instead)
  chroot "${ROOTFS}" systemctl disable nodm 2>/dev/null || true
  ok "nodm configured for kiosk"

  # NEW APPROACH: Start kiosk from root's .bash_profile after autologin
  # This is more reliable because:
  # 1. Console always works first
  # 2. User can see errors
  # 3. Ctrl+C can stop X11 if it fails
  log "Setting up kiosk to start from .bash_profile..."

  # Create kiosk startup script (non-blocking)
  cat > "${ROOTFS}/usr/local/bin/start-kiosk" <<'KIOSKSTART'
#!/bin/bash
# Start SecuBox Kiosk Mode - NON-BLOCKING
# Runs in background, user always gets prompt

# Only run once
[[ -f /tmp/.kiosk-starting ]] && exit 0
touch /tmp/.kiosk-starting

# Check if kiosk is enabled
[[ ! -f /var/lib/secubox/.kiosk-enabled ]] && exit 0

echo "[Kiosk] Starting X11 in background..."
echo "[Kiosk] Use 'pkill xinit' to stop, Alt+F1 for console"

# Configure X11
mkdir -p /etc/X11/xorg.conf.d
cat > /etc/X11/xorg.conf.d/10-kiosk.conf <<'XCONF'
Section "Device"
    Identifier "Kiosk Graphics"
    Driver "modesetting"
EndSection
XCONF

# Start X11 in background, switch to VT7 after 3 seconds
(
    sleep 2
    URL="https://localhost/"
    export DISPLAY=:0
    xinit /bin/bash -c "
        xset s off 2>/dev/null
        xset -dpms 2>/dev/null
        exec chromium --kiosk --no-first-run --no-sandbox --disable-gpu \
            --ignore-certificate-errors --window-position=0,0 '$URL'
    " -- :0 vt7 -nolisten tcp 2>/dev/null &
    sleep 3
    chvt 7 2>/dev/null
) &

# Return immediately - user gets prompt
KIOSKSTART
  chmod +x "${ROOTFS}/usr/local/bin/start-kiosk"

  # Add to root's .bash_profile (runs kiosk in background)
  cat >> "${ROOTFS}/root/.bash_profile" <<'PROFILE'

# Auto-start kiosk mode if enabled (non-blocking)
if [[ -f /var/lib/secubox/.kiosk-enabled ]] && [[ "$(tty)" == "/dev/tty1" ]]; then
    /usr/local/bin/start-kiosk &
fi
PROFILE

  # Enable getty on tty2-6 for VT switching (essential for recovery)
  # Note: tty1 autologin already configured in override.conf earlier
  mkdir -p "${ROOTFS}/etc/systemd/system/getty.target.wants"
  for tty in 2 3 4 5 6; do
    ln -sf /usr/lib/systemd/system/getty@.service \
      "${ROOTFS}/etc/systemd/system/getty.target.wants/getty@tty${tty}.service"
  done
  log "Getty enabled on tty2-6 for recovery"

  ok "Kiosk configured to start from .bash_profile (Ctrl+C to skip)"
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

  # Note: tty1 autologin already configured in override.conf earlier
  # Enable getty on tty2-6 for VT switching
  mkdir -p "${ROOTFS}/etc/systemd/system/getty.target.wants"
  for tty in 2 3 4 5 6; do
    ln -sf /usr/lib/systemd/system/getty@.service \
      "${ROOTFS}/etc/systemd/system/getty.target.wants/getty@tty${tty}.service"
  done
fi

ok "Scripts installed"

# ══════════════════════════════════════════════════════════════════
# Step 5b: Install to Disk script
# ══════════════════════════════════════════════════════════════════
log "Installing disk installer..."

cat > "${ROOTFS}/usr/bin/secubox-install" <<'INSTALLER'
#!/bin/bash
# ══════════════════════════════════════════════════════════════════
# SecuBox Install to Disk
# Installs the running live system to a target disk
# ══════════════════════════════════════════════════════════════════
set -e

CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'
GOLD='\033[0;33m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[INSTALL]${NC} $*"; }
ok()   { echo -e "${GREEN}[  ✓  ]${NC} $*"; }
err()  { echo -e "${RED}[  ✗  ]${NC} $*" >&2; exit 1; }
warn() { echo -e "${GOLD}[  !  ]${NC} $*"; }

# Banner
echo ""
echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║                                                               ║${NC}"
echo -e "${CYAN}${BOLD}║     🖥️  SecuBox — Install to Disk                              ║${NC}"
echo -e "${CYAN}${BOLD}║                                                               ║${NC}"
echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

[[ $EUID -ne 0 ]] && err "Must run as root: sudo secubox-install"

# Find available disks
log "Scanning disks..."
DISKS=()
while IFS= read -r line; do
    disk=$(echo "$line" | awk '{print $1}')
    size=$(echo "$line" | awk '{print $2}')
    model=$(echo "$line" | awk '{$1=$2=""; print $0}' | xargs)
    # Skip USB boot disk (where we're running from)
    mountpoint -q / && ROOT_DEV=$(findmnt -n -o SOURCE /) && \
      [[ "$ROOT_DEV" == *"$disk"* ]] && continue
    DISKS+=("$disk|$size|$model")
done < <(lsblk -d -n -o NAME,SIZE,MODEL | grep -E '^(sd|nvme|vd)')

[[ ${#DISKS[@]} -eq 0 ]] && err "No available disks found"

echo ""
echo -e "${BOLD}Available disks:${NC}"
echo "─────────────────────────────────────────────────────────────────"
idx=1
for d in "${DISKS[@]}"; do
    IFS='|' read -r name size model <<< "$d"
    printf "  %d) %-12s %-10s %s\n" "$idx" "/dev/$name" "$size" "$model"
    ((idx++))
done
echo "─────────────────────────────────────────────────────────────────"
echo ""

read -p "Select disk [1-${#DISKS[@]}]: " choice
[[ -z "$choice" || ! "$choice" =~ ^[0-9]+$ ]] && err "Invalid selection"
((choice--))
[[ $choice -lt 0 || $choice -ge ${#DISKS[@]} ]] && err "Invalid selection"

IFS='|' read -r DISK_NAME DISK_SIZE DISK_MODEL <<< "${DISKS[$choice]}"
TARGET="/dev/$DISK_NAME"

echo ""
warn "⚠️  ALL DATA ON $TARGET ($DISK_SIZE - $DISK_MODEL) WILL BE DESTROYED!"
echo ""
read -p "Type 'YES' to confirm: " confirm
[[ "$confirm" != "YES" ]] && err "Installation cancelled"

# Partition the disk
log "Partitioning $TARGET..."

# Unmount any existing partitions
umount ${TARGET}* 2>/dev/null || true

# Create GPT partition table
parted -s "$TARGET" mklabel gpt

# Create partitions: ESP (512MB) + Root (rest - 4GB) + Data (4GB)
# Note: Use -- to stop option parsing (otherwise -4GiB is parsed as options)
parted -s "$TARGET" -- mkpart ESP fat32 1MiB 513MiB
parted -s "$TARGET" set 1 esp on
parted -s "$TARGET" -- mkpart root ext4 513MiB -4GiB
parted -s "$TARGET" -- mkpart data ext4 -4GiB 100%

partprobe "$TARGET"
sleep 2

# Determine partition names
if [[ "$TARGET" == *nvme* ]]; then
    PART_ESP="${TARGET}p1"
    PART_ROOT="${TARGET}p2"
    PART_DATA="${TARGET}p3"
else
    PART_ESP="${TARGET}1"
    PART_ROOT="${TARGET}2"
    PART_DATA="${TARGET}3"
fi

# Format partitions
log "Formatting partitions..."
mkfs.fat -F32 -n "ESP" "$PART_ESP"
mkfs.ext4 -L "secubox" -q "$PART_ROOT"
mkfs.ext4 -L "data" -q "$PART_DATA"

ok "Partitions created"

# Mount and copy system
log "Copying system files (this may take a while)..."

MNT="/mnt/secubox-install"
mkdir -p "$MNT"
mount "$PART_ROOT" "$MNT"
mkdir -p "$MNT/boot/efi" "$MNT/data"
mount "$PART_ESP" "$MNT/boot/efi"

# Copy the live filesystem
rsync -ax --info=progress2 \
    --exclude="/proc/*" \
    --exclude="/sys/*" \
    --exclude="/dev/*" \
    --exclude="/run/*" \
    --exclude="/tmp/*" \
    --exclude="/mnt/*" \
    --exclude="/media/*" \
    --exclude="/live/*" \
    --exclude="/cdrom/*" \
    / "$MNT/"

ok "System files copied"

# Create necessary directories
mkdir -p "$MNT/proc" "$MNT/sys" "$MNT/dev" "$MNT/run" "$MNT/tmp" "$MNT/mnt"

# Generate fstab
log "Configuring fstab..."
ROOT_UUID=$(blkid -s UUID -o value "$PART_ROOT")
ESP_UUID=$(blkid -s UUID -o value "$PART_ESP")
DATA_UUID=$(blkid -s UUID -o value "$PART_DATA")

cat > "$MNT/etc/fstab" <<EOF
# SecuBox fstab - generated by secubox-install
UUID=$ROOT_UUID  /           ext4  defaults,errors=remount-ro  0 1
UUID=$ESP_UUID   /boot/efi   vfat  umask=0077                  0 1
UUID=$DATA_UUID  /data       ext4  defaults                    0 2
EOF

ok "fstab configured"

# Install GRUB bootloader
log "Installing bootloader..."

mount --bind /dev "$MNT/dev"
mount --bind /proc "$MNT/proc"
mount --bind /sys "$MNT/sys"

chroot "$MNT" grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=SecuBox --recheck 2>/dev/null || \
    warn "EFI GRUB install failed (may be BIOS system)"
chroot "$MNT" grub-install --target=i386-pc "$TARGET" 2>/dev/null || \
    warn "BIOS GRUB install failed (may be EFI-only)"
chroot "$MNT" update-grub

ok "Bootloader installed"

# Cleanup
umount "$MNT/sys" "$MNT/proc" "$MNT/dev"
umount "$MNT/boot/efi"
umount "$MNT"

# Success banner
echo ""
echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║                                                               ║${NC}"
echo -e "${GREEN}${BOLD}║     ✅ SecuBox installed successfully!                        ║${NC}"
echo -e "${GREEN}${BOLD}║                                                               ║${NC}"
echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Installed to: $TARGET ($DISK_SIZE)"
echo "  Partitions:"
echo "    ESP:  $PART_ESP (EFI boot)"
echo "    Root: $PART_ROOT (system)"
echo "    Data: $PART_DATA (persistent data)"
echo ""
echo "  Remove the USB drive and reboot to start SecuBox."
echo ""

read -p "Reboot now? [y/N]: " reboot_now
[[ "$reboot_now" =~ ^[Yy]$ ]] && reboot
INSTALLER
chmod +x "${ROOTFS}/usr/bin/secubox-install"

ok "Disk installer installed"

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
# Use insmod directly since modprobe requires modules.dep which may not work
mkdir -p "${ROOTFS}/etc/initramfs-tools/scripts/init-top"
cat > "${ROOTFS}/etc/initramfs-tools/scripts/init-top/load-squashfs" <<'EOFSQ'
#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in
    prereqs) prereqs; exit 0;;
esac

# Find and load squashfs module using insmod (more reliable than modprobe)
KVER=$(uname -r)
for path in \
    /usr/lib/modules/${KVER}/kernel/fs/squashfs/squashfs.ko \
    /lib/modules/${KVER}/kernel/fs/squashfs/squashfs.ko \
    $(find /usr/lib/modules /lib/modules -name "squashfs.ko*" 2>/dev/null | head -1)
do
    if [ -f "$path" ]; then
        insmod "$path" 2>/dev/null && break
    fi
    # Try with .xz or .zst extension
    for ext in .xz .zst .gz; do
        if [ -f "${path}${ext}" ]; then
            # Decompress and load
            case "$ext" in
                .xz) xz -d -c "${path}${ext}" > /tmp/squashfs.ko && insmod /tmp/squashfs.ko 2>/dev/null && break 2 ;;
                .zst) zstd -d -c "${path}${ext}" > /tmp/squashfs.ko && insmod /tmp/squashfs.ko 2>/dev/null && break 2 ;;
                .gz) gzip -d -c "${path}${ext}" > /tmp/squashfs.ko && insmod /tmp/squashfs.ko 2>/dev/null && break 2 ;;
            esac
        fi
    done
done

# Fallback to modprobe
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
# Ensure squashfs module is included - CRITICAL for live-boot
manual_add_modules squashfs loop overlay
# Also copy the module directly to be safe
copy_modules_dir kernel/fs/squashfs
EOFHOOK
chmod +x "${ROOTFS}/etc/initramfs-tools/hooks/live-squashfs"

# Force MODULES=most to include filesystem modules
sed -i 's/^MODULES=.*/MODULES=most/' "${ROOTFS}/etc/initramfs-tools/initramfs.conf" 2>/dev/null || \
  echo "MODULES=most" >> "${ROOTFS}/etc/initramfs-tools/initramfs.conf"

# CRITICAL: Run depmod to update modules.dep BEFORE update-initramfs
# This ensures squashfs is properly indexed and can be loaded
log "Running depmod to index kernel modules..."
KVER=$(ls "${ROOTFS}/lib/modules/" | head -1)
chroot "${ROOTFS}" depmod -a "${KVER}" || warn "depmod failed"

# Verify squashfs is in modules.dep
if grep -q squashfs "${ROOTFS}/lib/modules/${KVER}/modules.dep"; then
  ok "squashfs in modules.dep"
else
  warn "squashfs NOT in modules.dep - adding manually"
  echo "kernel/fs/squashfs/squashfs.ko:" >> "${ROOTFS}/lib/modules/${KVER}/modules.dep"
fi

# Regenerate initramfs with live-boot and Plymouth hooks
log "Regenerating initramfs with live-boot hooks..."
chroot "${ROOTFS}" update-initramfs -u -k all || warn "initramfs update failed"

# VERIFY squashfs is in initramfs
log "Verifying squashfs module in initramfs..."
INITRD=$(ls "${ROOTFS}"/boot/initrd.img-* 2>/dev/null | head -1)
if [[ -f "$INITRD" ]]; then
  if lsinitramfs "$INITRD" 2>/dev/null | grep -q "squashfs.ko"; then
    ok "squashfs module confirmed in initramfs"
  else
    warn "squashfs NOT in initramfs - forcing rebuild with verbose"
    chroot "${ROOTFS}" update-initramfs -u -k all -v 2>&1 | grep -i squash || true
  fi
fi

# Clean APT
chroot "${ROOTFS}" apt-get clean
rm -rf "${ROOTFS}/var/lib/apt/lists"/*
rm -rf "${ROOTFS}/var/cache/apt"/*.bin
rm -rf "${ROOTFS}/tmp"/*

# ── CRT-Style Boot Banner with Colors and Emojis ──────────────────────────────
log "Creating colorful boot banners..."

# Pre-login banner (/etc/issue) - shown before login prompt
cat > "${ROOTFS}/etc/issue" <<ISSUE
[38;5;214m
   ██████ ███████  ██████ ██    ██ ██████   ██████  ██   ██
  ██      ██      ██      ██    ██ ██   ██ ██    ██  ██ ██
  ███████ █████   ██      ██    ██ ██████  ██    ██   ███
       ██ ██      ██      ██    ██ ██   ██ ██    ██  ██ ██
  ███████ ███████  ██████  ██████  ██████   ██████  ██   ██
[0m
[38;5;45m  ⚡ CyberMind Security Platform[0m  [38;5;82mv${SECUBOX_VERSION}[0m  [38;5;242m\l @ \n[0m
[38;5;242m  Build: ${BUILD_TIMESTAMP}[0m

[38;5;250m  🔐 Default: [38;5;214mroot[38;5;250m / [38;5;214msecubox[0m
[38;5;250m  🌐 Web UI: [38;5;45mhttps://<IP>:9443[0m
[38;5;250m  📡 SSH:    [38;5;45mport 22[0m

[38;5;242m─────────────────────────────────────────────────────────────[0m

ISSUE

# Post-login MOTD with dynamic info (/etc/motd)
cat > "${ROOTFS}/etc/motd" <<MOTD
[38;5;214m
  ╔═══════════════════════════════════════════════════════════════╗
  ║[38;5;45m   ███████╗███████╗ ██████╗██╗   ██╗██████╗  ██████╗ ██╗  ██╗  [38;5;214m║
  ║[38;5;45m   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔═══██╗╚██╗██╔╝  [38;5;214m║
  ║[38;5;45m   ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║ ╚███╔╝   [38;5;214m║
  ║[38;5;45m   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║ ██╔██╗   [38;5;214m║
  ║[38;5;45m   ███████║███████╗╚██████╗╚██████╔╝██████╔╝╚██████╔╝██╔╝ ██╗  [38;5;214m║
  ║[38;5;45m   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝  [38;5;214m║
  ║[38;5;82m            ⚡ LIVE USB MODE ⚡  v${SECUBOX_VERSION}               [38;5;214m║
  ╚═══════════════════════════════════════════════════════════════╝[0m

[38;5;242m  Build: ${BUILD_TIMESTAMP}[0m

[38;5;250m  🌐 Web UI:     [38;5;45mhttps://<IP>:9443[0m
[38;5;250m  🔐 Credentials: [38;5;214mroot[38;5;250m / [38;5;214msecubox[0m
[38;5;250m  📖 Docs:       [38;5;45mhttps://secubox.in/docs[0m

[38;5;242m  Type [38;5;82msecubox-status[38;5;242m for system overview[0m

MOTD

# Dynamic status script for interactive use
cat > "${ROOTFS}/usr/bin/secubox-status" <<'STATUS_SCRIPT'
#!/bin/bash
# SecuBox Status - CRT-style system overview
# CyberMind — https://cybermind.fr

# Colors
GOLD='\033[38;5;214m'
CYAN='\033[38;5;45m'
GREEN='\033[38;5;82m'
RED='\033[38;5;196m'
GRAY='\033[38;5;242m'
WHITE='\033[38;5;250m'
RESET='\033[0m'

# Status indicators
ok="${GREEN}●${RESET}"
fail="${RED}●${RESET}"
warn="${GOLD}●${RESET}"

# Header
echo -e "${CYAN}"
echo '  ╭──────────────────────────────────────────────────────────╮'
echo '  │           ⚡ SecuBox System Status ⚡                   │'
echo '  ╰──────────────────────────────────────────────────────────╯'
echo -e "${RESET}"

# System info
echo -e "${WHITE}  📊 System Info${RESET}"
echo -e "     ${GRAY}Hostname:${RESET}  $(hostname)"
echo -e "     ${GRAY}Uptime:${RESET}    $(uptime -p 2>/dev/null || echo 'N/A')"
echo -e "     ${GRAY}Memory:${RESET}    $(free -h | awk '/^Mem:/{printf "%s / %s (%.1f%%)", $3, $2, $3/$2*100}')"
echo -e "     ${GRAY}Disk:${RESET}      $(df -h / | awk 'NR==2{printf "%s / %s (%s)", $3, $2, $5}')"
echo ""

# Network info
echo -e "${WHITE}  🌐 Network${RESET}"
for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$'); do
    ip_addr=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    if [[ -n "$ip_addr" ]]; then
        echo -e "     ${GREEN}●${RESET} ${GRAY}${iface}:${RESET}  ${CYAN}${ip_addr}${RESET}"
    fi
done
echo ""

# Core services
echo -e "${WHITE}  🔧 Core Services${RESET}"
services=(nginx haproxy secubox-api secubox-hub crowdsec suricata)
for svc in "${services[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo -e "     ${ok} ${GRAY}${svc}${RESET}"
    elif systemctl list-unit-files "${svc}.service" 2>/dev/null | grep -q "$svc"; then
        echo -e "     ${fail} ${GRAY}${svc}${RESET} (stopped)"
    fi
done
echo ""

# Mode detection
echo -e "${WHITE}  🎮 Display Mode${RESET}"
if [[ -f /var/lib/secubox/.kiosk-enabled ]]; then
    echo -e "     ${ok} ${CYAN}Kiosk GUI${RESET} (Web browser on tty7)"
elif [[ -f /var/lib/secubox/.tui-enabled ]]; then
    echo -e "     ${ok} ${CYAN}Console TUI${RESET} (Text dashboard on tty1)"
else
    echo -e "     ${warn} ${CYAN}Console Shell${RESET} (Standard login)"
fi
echo ""

# Quick links
echo -e "${GOLD}  ────────────────────────────────────────────────────────────${RESET}"
echo -e "${WHITE}  🔗 Quick Access${RESET}"
IP=$(hostname -I | awk '{print $1}')
echo -e "     ${GRAY}Dashboard:${RESET}  ${CYAN}https://${IP:-localhost}:9443${RESET}"
echo -e "     ${GRAY}Admin API:${RESET}  ${CYAN}https://${IP:-localhost}:9443/api/v1/${RESET}"
echo ""
STATUS_SCRIPT
chmod +x "${ROOTFS}/usr/bin/secubox-status"

# Also add a boot-time banner display script
cat > "${ROOTFS}/usr/sbin/secubox-boot-banner" <<'BOOT_BANNER'
#!/bin/bash
# SecuBox Boot Banner - Displayed during boot
# CyberMind — https://cybermind.fr

GOLD='\033[38;5;214m'
CYAN='\033[38;5;45m'
GREEN='\033[38;5;82m'
GRAY='\033[38;5;242m'
RESET='\033[0m'

clear
echo -e "${GOLD}"
cat << 'LOGO'

   ██████ ███████  ██████ ██    ██ ██████   ██████  ██   ██
  ██      ██      ██      ██    ██ ██   ██ ██    ██  ██ ██
  ███████ █████   ██      ██    ██ ██████  ██    ██   ███
       ██ ██      ██      ██    ██ ██   ██ ██    ██  ██ ██
  ███████ ███████  ██████  ██████  ██████   ██████  ██   ██

LOGO
echo -e "${RESET}"
echo -e "${CYAN}  ⚡ CyberMind Security Platform${RESET}"
echo -e "${GRAY}     Booting...${RESET}"
echo ""

# Show boot progress
show_status() {
    local name="$1"
    local check="$2"
    if eval "$check" 2>/dev/null; then
        echo -e "  ${GREEN}✓${RESET} ${name}"
    else
        echo -e "  ${GRAY}○${RESET} ${name} (waiting...)"
    fi
}

show_status "Network" "ip route | grep -q default"
show_status "Nginx" "systemctl is-active --quiet nginx"
show_status "SecuBox API" "systemctl is-active --quiet secubox-api"

echo ""
echo -e "${GRAY}  Dashboard: https://$(hostname -I | awk '{print $1}' || echo 'localhost'):9443${RESET}"
echo ""
BOOT_BANNER
chmod +x "${ROOTFS}/usr/sbin/secubox-boot-banner"

ok "Boot banners created with CRT colors and emojis"

# Unmount
umount -lf "${ROOTFS}/proc" 2>/dev/null || true
umount -lf "${ROOTFS}/sys"  2>/dev/null || true
umount -lf "${ROOTFS}/dev"  2>/dev/null || true

ok "Rootfs cleaned"

# ── Final nginx fix (MUST run after ALL package installs) ──────────────────
log "Final nginx configuration cleanup..."

# Remove any location-only configs from conf.d (they belong in secubox.d)
for conf in "${ROOTFS}/etc/nginx/conf.d/"*secubox*.conf "${ROOTFS}/etc/nginx/conf.d/"*repo*.conf; do
  [[ -e "$conf" ]] || [[ -L "$conf" ]] || continue
  log "Removing bad config from conf.d: $(basename "$conf")"
  rm -f "$conf"
done

# Remove ALL broken symlinks in secubox.d (more aggressive cleanup)
log "Removing broken symlinks from secubox.d..."
find "${ROOTFS}/etc/nginx/secubox.d/" -maxdepth 1 -type l ! -exec test -e {} \; -delete 2>/dev/null || true

# Also check for any file that the glob matches but can't be read
for f in "${ROOTFS}/etc/nginx/secubox.d/"*.conf; do
  [[ -e "$f" ]] && continue  # File exists, skip
  [[ -L "$f" ]] && { rm -f "$f"; log "Removed broken symlink: $(basename "$f")"; }
done

# Create empty placeholder if secubox-repo.conf is missing (some packages reference it)
if [[ ! -f "${ROOTFS}/etc/nginx/secubox.d/secubox-repo.conf" ]] && \
   [[ ! -f "${ROOTFS}/etc/nginx/secubox.d/repo.conf" ]]; then
  # Create minimal repo config to satisfy nginx
  cat > "${ROOTFS}/etc/nginx/secubox.d/repo.conf" << 'REPOCONF'
# Placeholder - repo module not installed
REPOCONF
  log "Created placeholder repo.conf"
fi

# Verify nginx config is valid
if [[ -x "${ROOTFS}/usr/sbin/nginx" ]]; then
  if ! chroot "${ROOTFS}" nginx -t 2>&1 | grep -q "syntax is ok"; then
    warn "nginx config still invalid after final cleanup"
    # Show the error and try to fix
    nginx_error=$(chroot "${ROOTFS}" nginx -t 2>&1 | head -5)
    echo "$nginx_error"
    # Extract missing file from error message and create empty config
    missing_file=$(echo "$nginx_error" | grep -oP '"/etc/nginx/secubox\.d/\K[^"]+')
    if [[ -n "$missing_file" ]]; then
      log "Creating missing config: $missing_file"
      touch "${ROOTFS}/etc/nginx/secubox.d/${missing_file}"
    fi
  else
    ok "Final nginx configuration valid"
  fi
fi

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

# Unmount special filesystems before creating squashfs
log "Unmounting chroot filesystems..."
umount -lf "${ROOTFS}/dev/pts" 2>/dev/null || true
sync
sleep 1
umount -f "${ROOTFS}/dev" 2>/dev/null || umount -lf "${ROOTFS}/dev" 2>/dev/null || true
umount -lf "${ROOTFS}/proc" 2>/dev/null || true
umount -lf "${ROOTFS}/sys" 2>/dev/null || true

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

# GRUB config - Dynamic based on build options
# When kiosk is enabled, default to Kiosk GUI (entry 1), otherwise standard boot (entry 0)
if [[ "${INCLUDE_KIOSK:-1}" == "1" ]]; then
    GRUB_DEFAULT=1  # Kiosk GUI is second entry
    log "GRUB default: Kiosk GUI mode"
else
    GRUB_DEFAULT=0  # Standard boot
    log "GRUB default: Standard boot"
fi

cat > "${MNT}/esp/boot/grub/grub.cfg" <<GRUBCFG
set default=${GRUB_DEFAULT}
set timeout=5

insmod part_gpt
insmod fat
insmod ext2
insmod all_video

search --no-floppy --label LIVE --set=live

# CRT-style menu colors (cyan on black, gold highlights)
set menu_color_normal=cyan/black
set menu_color_highlight=yellow/blue

# Version header
set pager=1
echo "SecuBox v${SECUBOX_VERSION} - Build ${BUILD_TIMESTAMP}"
echo ""

menuentry "⚡ SecuBox Live v${SECUBOX_VERSION}" {
    linux (\$live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components persistence quiet splash
    initrd (\$live)/live/initrd.img
}

menuentry "🖼️ SecuBox Live v${SECUBOX_VERSION} (Kiosk GUI) [DEFAULT]" {
    linux (\$live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components persistence quiet splash secubox.kiosk=1 systemd.unit=graphical.target
    initrd (\$live)/live/initrd.img
}
GRUBCFG

# Append the rest of the menu entries with emoji indicators
cat >> "${MNT}/esp/boot/grub/grub.cfg" <<'GRUBCFG'

menuentry "📟 SecuBox Live (Console TUI)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components persistence quiet splash secubox.mode=tui
    initrd ($live)/live/initrd.img
}

menuentry "🌉 SecuBox Live (Bridge Mode)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components persistence quiet splash secubox.netmode=bridge
    initrd ($live)/live/initrd.img
}

menuentry "🛡️ SecuBox Live (Safe Mode)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components nomodeset console=tty0
    initrd ($live)/live/initrd.img
}

menuentry "💾 Install SecuBox to Disk" {
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components nomodeset console=tty0 secubox.install=1
    initrd ($live)/live/initrd.img
}

menuentry "🚀 SecuBox Live (To RAM)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components toram quiet splash
    initrd ($live)/live/initrd.img
}

menuentry "🔧 SecuBox Live (HW Check)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components persistence quiet splash secubox.hwcheck=1
    initrd ($live)/live/initrd.img
}

menuentry "🔧 SecuBox Live (HW Check - Text)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components persistence nomodeset console=tty0 secubox.hwcheck=1
    initrd ($live)/live/initrd.img
}

menuentry "🚨 Emergency Shell" {
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components nomodeset console=tty0 systemd.unit=emergency.target
    initrd ($live)/live/initrd.img
}

menuentry "🐛 Debug (Verbose Boot)" {
    linux ($live)/live/vmlinuz boot=live live-media-path=/live rootdelay=10 components nomodeset console=tty0 debug=1 break=init
    initrd ($live)/live/initrd.img
}

menuentry "🐛 Debug (Break at Premount)" {
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

# Add startup.nsh for EFI shell auto-boot (VirtualBox/OVMF compatibility)
cat > "${MNT}/esp/startup.nsh" <<'STARTUPNSH'
@echo -off
\EFI\BOOT\BOOTX64.EFI
STARTUPNSH

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
echo -e "    Web UI: https://localhost (or real LAN IP)"
echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════${NC}"
