#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox-DEB — build-image.sh
#  debootstrap → image .img flashable sur eMMC/SD (arm64) ou .vdi (x64)
#  Usage : sudo bash image/build-image.sh --board mochabin [OPTIONS]
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# ── Defaults ──────────────────────────────────────────────────────
BOARD="mochabin"
SUITE="bookworm"
IMG_SIZE="4G"         # Taille de l'image totale
ROOT_SIZE="2.5G"      # Taille partition rootfs
DATA_SIZE="1G"        # Taille partition data
OUT_DIR="${REPO_DIR}/output"
KEEP_ROOTFS=0
APT_MIRROR="http://deb.debian.org/debian"
APT_SECUBOX="https://apt.secubox.in"
CONVERT_VDI=0         # Convertir en VDI pour VirtualBox
USE_LOCAL_CACHE=0     # Utiliser cache APT local
LOCAL_CACHE_PORT="3142"
LOCAL_REPO_PORT="8080"
SLIPSTREAM_DEBS=1     # Intégrer les .deb locaux dans l'image (default: ON)

# SecuBox versioning
SECUBOX_VERSION="1.7.0"
BUILD_TIMESTAMP=$(date '+%Y-%m-%d %H:%M')

RED='\033[0;31m'; CYAN='\033[0;36m'; GOLD='\033[0;33m'
GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[build]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK ]${NC} $*"; }
err()  { echo -e "${RED}[FAIL ]${NC} $*" >&2; exit 1; }
warn() { echo -e "${GOLD}[ WARN]${NC} $*"; }

# ── Parse args ────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: sudo bash build-image.sh [OPTIONS]

  --board   BOARD    mochabin|espressobin-v7|espressobin-ultra|vm-x64 (défaut: mochabin)
  --suite   SUITE    Debian suite (défaut: bookworm)
  --out     DIR      Répertoire de sortie (défaut: ./output)
  --size    SIZE     Taille totale image (défaut: 4G)
  --vdi               Convertir en VDI (VirtualBox) en plus du raw
  --local-cache      Utiliser cache APT local (apt-cacher-ng + repo local)
  --slipstream       Intégrer les .deb de output/debs/ dans l'image
  --keep-rootfs      Garder le rootfs décompressé après build
  --help             Cette aide

Boards supportés :
  mochabin           Marvell Armada 7040 (arm64) — SecuBox Pro
  espressobin-v7     Marvell Armada 3720 (arm64) — SecuBox Lite
  espressobin-ultra  Marvell Armada 3720 (arm64) — SecuBox Lite+
  vm-x64             VirtualBox/QEMU (amd64) — Test/Dev
  vm-arm64           QEMU virt (arm64) — Test/Dev ARM64

Cache local :
  Exécuter d'abord : sudo bash scripts/setup-local-cache.sh
  Puis builder avec : sudo bash image/build-image.sh --board vm-x64 --local-cache

EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --board)       BOARD="$2";        shift 2 ;;
    --suite)       SUITE="$2";        shift 2 ;;
    --out)         OUT_DIR="$2";      shift 2 ;;
    --size)        IMG_SIZE="$2";     shift 2 ;;
    --vdi)         CONVERT_VDI=1;      shift   ;;
    --local-cache) USE_LOCAL_CACHE=1;  shift   ;;
    --slipstream)  SLIPSTREAM_DEBS=1;  shift   ;;
    --keep-rootfs) KEEP_ROOTFS=1;      shift   ;;
    --help|-h)     usage ;;
    *) err "Argument inconnu: $1" ;;
  esac
done

# ── Vérifications ─────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "Ce script doit être exécuté en root (sudo)"

BOARD_DIR="${REPO_DIR}/board/${BOARD}"
[[ -d "$BOARD_DIR" ]] || err "Board inconnu: ${BOARD} (pas de dossier board/${BOARD}/)"

# Charger config du board
source "${BOARD_DIR}/config.mk" 2>/dev/null || true

# Redirect to build-rpi-usb.sh for Raspberry Pi boards
if [[ "${USE_RPI_SCRIPT:-0}" == "1" ]] || [[ "$BOARD" == "rpi400" ]] || [[ "$BOARD" == "rpi4" ]]; then
  log "Raspberry Pi board detected - using build-rpi-usb.sh"
  RPI_ARGS="--out ${OUT_DIR}"
  [[ $SLIPSTREAM_DEBS -eq 1 ]] && RPI_ARGS="$RPI_ARGS --slipstream"
  exec bash "${SCRIPT_DIR}/build-rpi-usb.sh" $RPI_ARGS
fi

# Déterminer l'architecture
DEBIAN_ARCH="${DEBIAN_ARCH:-arm64}"
IS_X64=0
IS_ARM64=0
NEED_QEMU=0

case "$DEBIAN_ARCH" in
  amd64)
    IS_X64=1
    HOST_ARCH=$(uname -m)
    [[ "$HOST_ARCH" != "x86_64" ]] && NEED_QEMU=1
    ;;
  arm64)
    IS_ARM64=1
    HOST_ARCH=$(uname -m)
    [[ "$HOST_ARCH" != "aarch64" ]] && NEED_QEMU=1
    ;;
  *)
    err "Architecture non supportée: $DEBIAN_ARCH"
    ;;
esac

# Vérifier outils requis
REQUIRED_TOOLS="debootstrap parted mkfs.fat mkfs.ext4 rsync"
# mkimage (u-boot-tools) est optionnel mais recommandé pour ARM
if [[ $IS_ARM64 -eq 1 ]] && [[ $NEED_QEMU -eq 1 ]]; then
  REQUIRED_TOOLS="$REQUIRED_TOOLS qemu-aarch64-static"
fi
if [[ $IS_X64 -eq 1 ]] && [[ $CONVERT_VDI -eq 1 ]]; then
  REQUIRED_TOOLS="$REQUIRED_TOOLS qemu-img"
fi

for cmd in $REQUIRED_TOOLS; do
  command -v "$cmd" >/dev/null || err "Manquant: $cmd"
done

# ── Local cache detection ─────────────────────────────────────
if [[ $USE_LOCAL_CACHE -eq 1 ]]; then
  LOCAL_CACHE_HOST="127.0.0.1"

  # Vérifier apt-cacher-ng
  if curl -sf "http://${LOCAL_CACHE_HOST}:${LOCAL_CACHE_PORT}" >/dev/null 2>&1; then
    APT_MIRROR="http://${LOCAL_CACHE_HOST}:${LOCAL_CACHE_PORT}/deb.debian.org/debian"
    log "Cache APT local détecté : ${APT_MIRROR}"
  else
    warn "apt-cacher-ng non accessible — utilisation du miroir distant"
  fi

  # Vérifier repo local SecuBox
  if curl -sf "http://${LOCAL_CACHE_HOST}:${LOCAL_REPO_PORT}/dists/${SUITE}/Release" >/dev/null 2>&1; then
    APT_SECUBOX="http://${LOCAL_CACHE_HOST}:${LOCAL_REPO_PORT}"
    log "Repo SecuBox local détecté : ${APT_SECUBOX}"
  else
    warn "Repo local SecuBox non accessible — fallback apt.secubox.in"
  fi
fi

# ── Setup ─────────────────────────────────────────────────────────
mkdir -p "$OUT_DIR"
WORK_DIR=$(mktemp -d /tmp/secubox-build-XXXXXX)
ROOTFS="${WORK_DIR}/rootfs"
IMG_FILE="${OUT_DIR}/secubox-${BOARD}-${SUITE}.img"

log "══════════════════════════════════════════════════════════"
log "Board       : ${BOLD}${BOARD}${NC}"
log "Architecture: ${BOLD}${DEBIAN_ARCH}${NC}"
log "Suite       : ${SUITE}"
log "Image       : ${IMG_FILE}"
log "Work dir    : ${WORK_DIR}"
log "APT Mirror  : ${APT_MIRROR}"
log "SecuBox Repo: ${APT_SECUBOX}"
[[ $USE_LOCAL_CACHE -eq 1 ]] && log "Local Cache : ${GREEN}enabled${NC}"
[[ $SLIPSTREAM_DEBS -eq 1 ]] && log "Slipstream  : ${GREEN}enabled${NC}"
log "══════════════════════════════════════════════════════════"

cleanup() {
  log "Nettoyage..."
  umount -lf "${ROOTFS}/proc" 2>/dev/null || true
  umount -lf "${ROOTFS}/sys"  2>/dev/null || true
  umount -lf "${ROOTFS}/dev"  2>/dev/null || true
  umount -lf "${ROOTFS}"      2>/dev/null || true
  [[ -n "${LOOP:-}" ]] && losetup -d "${LOOP}" 2>/dev/null || true
  [[ $KEEP_ROOTFS -eq 0 ]] && rm -rf "${WORK_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

# ── Étape 1 : Debootstrap ─────────────────────────────────────────
log "1/7 Debootstrap ${SUITE} ${DEBIAN_ARCH}..."
mkdir -p "${ROOTFS}"

DEBOOTSTRAP_OPTS="--arch=${DEBIAN_ARCH}"
INCLUDE_PKGS="systemd,systemd-sysv,dbus,netplan.io,nftables,openssh-server"
INCLUDE_PKGS+=",python3,python3-pip,nginx,curl,wget,ca-certificates,gnupg,apt-transport-https"
INCLUDE_PKGS+=",iproute2,iputils-ping,ethtool,net-tools,wireguard-tools"
INCLUDE_PKGS+=",sudo,less,vim-tiny,logrotate,cron,rsync,jq,dnsmasq"

if [[ $IS_X64 -eq 1 ]]; then
  # x64 : ajouter GRUB EFI + linux-image
  INCLUDE_PKGS+=",grub-efi-amd64,linux-image-amd64,efibootmgr"
elif [[ $IS_ARM64 -eq 1 ]]; then
  # arm64 : ajouter linux-image pour tous les boards ARM
  INCLUDE_PKGS+=",linux-image-arm64"
  if [[ "${BOARD}" == "vm-arm64" ]]; then
    # arm64 VM : ajouter aussi GRUB EFI arm64
    INCLUDE_PKGS+=",grub-efi-arm64,efibootmgr"
  fi
fi

if [[ $NEED_QEMU -eq 1 ]]; then
  DEBOOTSTRAP_OPTS+=" --foreign"
fi

debootstrap ${DEBOOTSTRAP_OPTS} \
  --include="${INCLUDE_PKGS}" \
  "${SUITE}" "${ROOTFS}" "${APT_MIRROR}"

# QEMU pour cross-arch
if [[ $NEED_QEMU -eq 1 ]]; then
  if [[ $IS_ARM64 -eq 1 ]]; then
    cp /usr/bin/qemu-aarch64-static "${ROOTFS}/usr/bin/"
  elif [[ $IS_X64 -eq 1 ]]; then
    cp /usr/bin/qemu-x86_64-static "${ROOTFS}/usr/bin/" 2>/dev/null || true
  fi
  chroot "${ROOTFS}" /debootstrap/debootstrap --second-stage
fi

ok "Debootstrap terminé"

# ── Étape 2 : Configuration base ──────────────────────────────────
log "2/7 Configuration système de base..."

# Monter les filesystems spéciaux
mount -t proc proc   "${ROOTFS}/proc"
mount -t sysfs sysfs "${ROOTFS}/sys"
mount --bind /dev    "${ROOTFS}/dev"

# Hostname
cat > "${ROOTFS}/etc/hostname" <<< "secubox-${BOARD}"

# /etc/hosts
cat > "${ROOTFS}/etc/hosts" <<EOF
127.0.0.1  localhost secubox.local
127.0.1.1  secubox-${BOARD} secubox
::1        localhost ip6-localhost ip6-loopback
EOF

# fstab
if [[ $IS_X64 -eq 1 ]]; then
  cat > "${ROOTFS}/etc/fstab" <<EOF
# SecuBox fstab — VM x64
LABEL=rootfs   /       ext4  defaults,noatime,commit=60  0  1
LABEL=data     /data   ext4  defaults,noatime             0  2
LABEL=ESP      /boot/efi  vfat  umask=0077              0  0
tmpfs          /run/secubox  tmpfs  mode=0755  0  0
EOF
else
  cat > "${ROOTFS}/etc/fstab" <<EOF
# SecuBox fstab — ARM
LABEL=rootfs   /       ext4  defaults,noatime,commit=60  0  1
LABEL=data     /data   ext4  defaults,noatime             0  2
LABEL=boot     /boot   vfat  defaults,noatime             0  0
tmpfs          /run/secubox  tmpfs  mode=0755  0  0
EOF
fi

# locale
chroot "${ROOTFS}" bash -c "locale-gen en_US.UTF-8 || true"
chroot "${ROOTFS}" bash -c "update-locale LANG=en_US.UTF-8 || true"

# Mot de passe root par défaut (à changer au premier boot)
chroot "${ROOTFS}" bash -c 'echo "root:secubox" | chpasswd'
log "Mot de passe root par défaut: secubox"

# Autoriser SSH root login
sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' "${ROOTFS}/etc/ssh/sshd_config"
sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' "${ROOTFS}/etc/ssh/sshd_config"
log "SSH root login activé"

# timezone
echo "Europe/Paris" > "${ROOTFS}/etc/timezone"
chroot "${ROOTFS}" dpkg-reconfigure -f noninteractive tzdata 2>/dev/null || true

# netplan de base
install -d "${ROOTFS}/etc/netplan"
cp "${BOARD_DIR}/netplan/00-secubox.yaml" "${ROOTFS}/etc/netplan/"

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

# Network fallback script - DHCP with smart auto-IP collision avoidance
cat > "${ROOTFS}/usr/sbin/secubox-net-fallback" <<'FALLBACK'
#!/bin/bash
# SecuBox Network Fallback - DHCP first, then smart auto-IP with ARP collision detection
# Avoids IP conflicts when multiple SecuBox devices are on same network
logger -t secubox-net "Network fallback starting..."

# Fallback network (SecuBox default when no DHCP)
FALLBACK_NETWORK="192.168.255"
FALLBACK_GW="192.168.255.1"
# IP range for auto-assignment (avoid .1 gateway and .255 broadcast)
IP_START=100
IP_END=250

# Check if IP is in use via ARP probe (RFC 5227)
# Returns 0 if IP is FREE, 1 if IP is TAKEN
check_ip_free() {
    local ip="$1"
    local iface="$2"

    # Send ARP probe (src=0.0.0.0, dst=target IP)
    # If we get a reply, the IP is taken
    if command -v arping &>/dev/null; then
        # arping returns 0 if reply received (IP taken), 1 if no reply (IP free)
        if arping -D -q -c 2 -w 2 -I "$iface" "$ip" 2>/dev/null; then
            return 0  # No reply = IP is free
        else
            return 1  # Got reply = IP is taken
        fi
    else
        # Fallback: ping check (less reliable but works)
        if ping -c 1 -W 1 "$ip" &>/dev/null; then
            return 1  # Got reply = IP is taken
        else
            return 0  # No reply = probably free
        fi
    fi
}

# Find a free IP in the fallback range using ARP probing
find_free_ip() {
    local iface="$1"
    local mac=$(cat /sys/class/net/$iface/address 2>/dev/null | tr -d ':')

    # Generate a pseudo-random starting point based on MAC address
    # This spreads devices across the range to reduce collision probability
    local mac_seed=$(printf "%d" "0x${mac:8:4}" 2>/dev/null || echo "12345")
    local range=$((IP_END - IP_START))
    local start_offset=$((mac_seed % range))

    logger -t secubox-net "Searching for free IP in ${FALLBACK_NETWORK}.${IP_START}-${IP_END} (seed offset: $start_offset)"

    # Try IPs starting from our MAC-based offset, wrapping around
    for ((i=0; i<range; i++)); do
        local offset=$(( (start_offset + i) % range ))
        local test_suffix=$((IP_START + offset))
        local test_ip="${FALLBACK_NETWORK}.${test_suffix}"

        if check_ip_free "$test_ip" "$iface"; then
            logger -t secubox-net "Found free IP: $test_ip"
            echo "$test_ip"
            return 0
        else
            logger -t secubox-net "IP $test_ip is in use, trying next..."
        fi
    done

    logger -t secubox-net "ERROR: No free IP found in range!"
    return 1
}

# Announce our IP via gratuitous ARP (alert other devices)
announce_ip() {
    local ip="$1"
    local iface="$2"

    if command -v arping &>/dev/null; then
        # Send gratuitous ARP to announce our presence
        arping -A -c 3 -I "$iface" "$ip" 2>/dev/null &
        logger -t secubox-net "Announced IP $ip via gratuitous ARP"
    fi
}

# Common gateway IPs to probe for existing networks
GATEWAYS="192.168.1.1 192.168.0.1 192.168.2.1 192.168.255.1 10.0.0.1 10.0.1.1 172.16.0.1"

discover_lan() {
    local iface="$1"
    for gw in $GATEWAYS; do
        local subnet_base="${gw%.*}"

        # Find a free IP in this subnet
        local test_ip
        for suffix in 250 249 248 251 252; do
            test_ip="${subnet_base}.${suffix}"
            if check_ip_free "$test_ip" "$iface"; then
                break
            fi
        done

        # Temporarily add IP to test gateway reachability
        ip addr add "${test_ip}/24" dev "$iface" 2>/dev/null

        if ping -c 1 -W 1 -I "$iface" "$gw" &>/dev/null; then
            logger -t secubox-net "Discovered gateway $gw on $iface"
            ip route add default via "$gw" dev "$iface" 2>/dev/null || true
            echo "nameserver $gw" > /etc/resolv.conf
            echo "nameserver 8.8.8.8" >> /etc/resolv.conf
            echo "nameserver 1.1.1.1" >> /etc/resolv.conf
            announce_ip "$test_ip" "$iface"
            logger -t secubox-net "Auto-configured $iface: ${test_ip}/24 via $gw"
            return 0
        fi

        ip addr del "${test_ip}/24" dev "$iface" 2>/dev/null
    done
    return 1
}

# Configure fallback network with collision-free IP
configure_fallback() {
    local iface="$1"

    logger -t secubox-net "Configuring fallback network on $iface"

    # Find a free IP in the fallback range
    local free_ip
    free_ip=$(find_free_ip "$iface")

    if [[ -z "$free_ip" ]]; then
        # Last resort: use MAC-based IP
        local mac=$(cat /sys/class/net/$iface/address 2>/dev/null | tr -d ':')
        local mac_suffix=$(printf "%d" "0x${mac:8:4}" 2>/dev/null || echo "200")
        mac_suffix=$((100 + (mac_suffix % 150)))
        free_ip="${FALLBACK_NETWORK}.${mac_suffix}"
        logger -t secubox-net "Using MAC-based fallback IP: $free_ip"
    fi

    # Configure the IP
    ip addr add "${free_ip}/24" dev "$iface" 2>/dev/null

    # Check if gateway exists
    if ping -c 1 -W 1 "$FALLBACK_GW" &>/dev/null; then
        ip route add default via "$FALLBACK_GW" dev "$iface" 2>/dev/null || true
        echo "nameserver $FALLBACK_GW" > /etc/resolv.conf
    fi
    echo "nameserver 8.8.8.8" >> /etc/resolv.conf
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf

    # Announce our IP
    announce_ip "$free_ip" "$iface"

    logger -t secubox-net "Fallback configured: $iface = $free_ip"
    return 0
}

# Wait for system to settle
sleep 10
GOT_IP=0

# Process each network interface
for iface in /sys/class/net/*; do
    [ -e "$iface" ] || continue
    IFACE=$(basename "$iface")

    # Skip virtual interfaces
    case "$IFACE" in
        lo|dummy*|docker*|veth*|br-*|virbr*) continue ;;
    esac

    # Only process physical network interfaces
    case "$IFACE" in
        e*|w*|lan*|eth*|wan*) ;;
        *) continue ;;
    esac

    ip link set "$IFACE" up 2>/dev/null
    sleep 2  # Wait for link

    # Check if already has valid IP
    CURRENT_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | grep -v '^169\.254\.' | head -1)
    if [[ -n "$CURRENT_IP" ]]; then
        logger -t secubox-net "Interface $IFACE already has IP $CURRENT_IP"
        GOT_IP=1
        continue
    fi

    # Try DHCP first
    logger -t secubox-net "Requesting DHCP on $IFACE..."
    if command -v dhclient &>/dev/null; then
        timeout 30 dhclient -1 -v "$IFACE" 2>&1 | logger -t secubox-net || true
    else
        networkctl reconfigure "$IFACE" 2>/dev/null || true
        sleep 15
    fi

    # Check if DHCP succeeded
    CURRENT_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | grep -v '^169\.254\.' | head -1)
    if [[ -n "$CURRENT_IP" ]]; then
        logger -t secubox-net "DHCP succeeded on $IFACE: $CURRENT_IP"
        GOT_IP=1
        continue
    fi

    # DHCP failed - try auto-discovery then fallback
    if [[ "$IFACE" == e* ]] || [[ "$IFACE" == lan* ]] || [[ "$IFACE" == eth* ]] || [[ "$IFACE" == wan* ]]; then
        logger -t secubox-net "DHCP failed on $IFACE, trying LAN auto-discovery..."
        if discover_lan "$IFACE"; then
            logger -t secubox-net "LAN auto-discovery succeeded on $IFACE"
            GOT_IP=1
        else
            logger -t secubox-net "Auto-discovery failed, using fallback network..."
            if configure_fallback "$IFACE"; then
                GOT_IP=1
            fi
        fi
    fi
done

# Final status
if [[ "$GOT_IP" -eq 1 ]]; then
    logger -t secubox-net "Network configuration complete"
else
    logger -t secubox-net "WARNING: No network configured!"
fi
FALLBACK
chmod +x "${ROOTFS}/usr/sbin/secubox-net-fallback"

# Systemd service for network fallback
cat > "${ROOTFS}/etc/systemd/system/secubox-net-fallback.service" <<'NETSVC'
[Unit]
Description=SecuBox Network Fallback
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/secubox-net-fallback
RemainAfterExit=yes
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
NETSVC
chroot "${ROOTFS}" systemctl enable secubox-net-fallback.service 2>/dev/null || true

ok "Configuration base terminée"

# ── Étape 3 : APT SecuBox + paquets ──────────────────────────────
log "3/7 Installation paquets SecuBox..."

# Install Python dependencies FIRST (required by SecuBox packages)
log "Installing Python dependencies..."
chroot "${ROOTFS}" apt-get install -y -q python3-pip python3-venv 2>/dev/null || true
chroot "${ROOTFS}" pip3 install --break-system-packages -q \
  fastapi uvicorn python-jose httpx jinja2 tomli pyroute2 psutil pydantic 2>&1 | tail -5 || true
ok "Python dependencies installed"

# Ajouter repo SecuBox (si disponible)
SECUBOX_REPO_OK=0
if [[ "$APT_SECUBOX" == "http://127.0.0.1:"* ]]; then
  # Repo local sans signature GPG (pour tests)
  if curl -sf "${APT_SECUBOX}/dists/${SUITE}/Release" >/dev/null 2>&1; then
    cat > "${ROOTFS}/etc/apt/sources.list.d/secubox.list" <<EOF
deb [trusted=yes] ${APT_SECUBOX} ${SUITE} main
EOF
    SECUBOX_REPO_OK=1
    log "Repo local SecuBox configuré (trusted=yes)"
  fi
elif curl -sf "${APT_SECUBOX}/secubox-keyring.gpg" -o "${ROOTFS}/usr/share/keyrings/secubox.gpg" 2>/dev/null; then
  cat > "${ROOTFS}/etc/apt/sources.list.d/secubox.list" <<EOF
deb [signed-by=/usr/share/keyrings/secubox.gpg] ${APT_SECUBOX} ${SUITE} main
EOF
  SECUBOX_REPO_OK=1
fi

if [[ $SECUBOX_REPO_OK -eq 1 ]]; then
  chroot "${ROOTFS}" apt-get update -q
  chroot "${ROOTFS}" apt-get install -y -q secubox-full || warn "secubox-full non disponible"
else
  warn "APT repo SecuBox non disponible — skip (Phase 4)"
fi

# ── Pre-install Python dependencies (BEFORE slipstream) ───────────────────
log "Pre-installing Python dependencies for SecuBox modules..."
install -d -m 755 "${ROOTFS}/usr/lib/systemd/system"
install -d -m 755 "${ROOTFS}/etc/systemd/system"
chroot "${ROOTFS}" pip3 install --break-system-packages -q \
  fastapi uvicorn[standard] python-jose[cryptography] httpx \
  jinja2 tomli pyroute2 psutil authlib aiosqlite aiofiles \
  pydantic toml netifaces 2>/dev/null || warn "pip install partiel"
ok "Python dependencies installed"

# Slipstream: intégrer les .deb locaux directement
if [[ $SLIPSTREAM_DEBS -eq 1 ]]; then
  # Check output/debs/ first (fresh builds), then output/
  if [[ -d "${REPO_DIR}/output/debs" ]] && ls "${REPO_DIR}/output/debs"/secubox-*.deb >/dev/null 2>&1; then
    DEBS_DIR="${REPO_DIR}/output/debs"
  elif [[ -d "${REPO_DIR}/output" ]] && ls "${REPO_DIR}/output"/secubox-*.deb >/dev/null 2>&1; then
    DEBS_DIR="${REPO_DIR}/output"
  else
    DEBS_DIR="${REPO_DIR}/output/debs"
  fi
  if [[ -d "${DEBS_DIR}" ]] && ls "${DEBS_DIR}"/secubox-*.deb >/dev/null 2>&1; then
    log "Slipstream: installation des paquets locaux..."
    install -d "${ROOTFS}/tmp/secubox-debs"
    cp "${DEBS_DIR}"/secubox-*.deb "${ROOTFS}/tmp/secubox-debs/"
    SLIP_COUNT=$(ls "${DEBS_DIR}"/secubox-*.deb 2>/dev/null | wc -l)
    log "Slipstream: ${SLIP_COUNT} packages to install"

    # Installer secubox-core en premier (dépendance)
    if ls "${ROOTFS}/tmp/secubox-debs/secubox-core_"*.deb >/dev/null 2>&1; then
      log "Installing secubox-core (dependency)..."
      chroot "${ROOTFS}" bash -c 'dpkg -i --force-depends /tmp/secubox-debs/secubox-core_*.deb' 2>/dev/null || true
    fi

    # Installer tous les autres paquets
    log "Installing all packages..."
    chroot "${ROOTFS}" bash -c 'dpkg -i --force-depends --force-overwrite /tmp/secubox-debs/*.deb' 2>&1 | \
      grep -v "^dpkg: warning" | grep -v "^Selecting\|^Preparing\|^Unpacking\|^Setting up" | head -30 || true

    # Configure packages (skip apt-get -f as pip provides Python deps)
    chroot "${ROOTFS}" dpkg --configure -a --force-confold 2>/dev/null || true

    # Count installed
    INSTALLED_COUNT=$(chroot "${ROOTFS}" dpkg -l 'secubox-*' 2>/dev/null | grep "^ii" | wc -l)

    # Nettoyer
    rm -rf "${ROOTFS}/tmp/secubox-debs"
    ok "Slipstream: ${INSTALLED_COUNT}/${SLIP_COUNT} paquets installés"

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

  else
    warn "Slipstream: pas de secubox-*.deb dans output/ ou output/debs/"
  fi
fi

# VirtualBox/QEMU Guest Tools pour VM
if [[ $IS_X64 -eq 1 ]] || [[ "${BOARD}" == "vm-arm64" ]]; then
  log "Installation des outils VM..."
  chroot "${ROOTFS}" bash -c "DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    qemu-guest-agent 2>/dev/null" || true

  # VirtualBox Guest Additions (non-interactive)
  chroot "${ROOTFS}" bash -c "DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    virtualbox-guest-utils 2>/dev/null" || warn "VBox Guest Additions non installées"

  # Enable guest agent
  chroot "${ROOTFS}" systemctl enable qemu-guest-agent 2>/dev/null || true
  ok "Outils VM installés"
fi

ok "Paquets installés"

# ── Initramfs hooks pour ARM (sdhci-xenon pour eMMC + mv88e6xxx blacklist) ──
if [[ $IS_ARM64 -eq 1 ]] && [[ "${BOARD}" != "vm-arm64" ]]; then
  log "Installation hooks initramfs (sdhci-xenon + mv88e6xxx blacklist)..."

  # Hook 1: sdhci-xenon pour support eMMC Armada 3720
  cat > "${ROOTFS}/etc/initramfs-tools/hooks/sdhci-xenon" <<'HOOK'
#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0;; esac
. /usr/share/initramfs-tools/hook-functions
# Armada 3720 eMMC support
manual_add_modules sdhci_xenon
manual_add_modules sdhci
manual_add_modules mmc_block
manual_add_modules mmc_core
manual_add_modules phy_mvebu_a3700_comphy
HOOK
  chmod +x "${ROOTFS}/etc/initramfs-tools/hooks/sdhci-xenon"

  # Hook 2: Blacklist mv88e6xxx DSA switch driver during initramfs
  # Prevents probe loop that causes boot failures on ESPRESSObin/MOCHAbin
  cat > "${ROOTFS}/etc/initramfs-tools/hooks/mv88e6xxx-blacklist" <<'HOOK'
#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0;; esac
. /usr/share/initramfs-tools/hook-functions
# Blacklist DSA switch driver during initramfs to prevent probe loop
mkdir -p "${DESTDIR}/etc/modprobe.d"
cat > "${DESTDIR}/etc/modprobe.d/mv88e6xxx-initramfs.conf" <<'MODPROBE'
# Blacklist DSA switch driver during initramfs
# Driver loads after rootfs mount via systemd-modules-load
blacklist mv88e6xxx
blacklist mv88e6085
blacklist dsa_core
MODPROBE
HOOK
  chmod +x "${ROOTFS}/etc/initramfs-tools/hooks/mv88e6xxx-blacklist"

  # Also create the modprobe.d config in rootfs for good measure
  mkdir -p "${ROOTFS}/etc/modprobe.d"
  cat > "${ROOTFS}/etc/modprobe.d/mv88e6xxx-delay.conf" <<'MODPROBE'
# Delay mv88e6xxx load to avoid probe loop during boot
# The driver is blacklisted in initramfs and loads after rootfs mount
softdep mv88e6xxx pre: mmc_block
softdep dsa_core pre: mmc_block
MODPROBE

  # SDHCI quirks for xenon-sdhci DDR timing issues on ESPRESSObin eMMC
  cat > "${ROOTFS}/etc/modprobe.d/sdhci-xenon-fix.conf" <<'MODPROBE'
# Fix xenon-sdhci DDR timing issues on Armada 3720 eMMC
# SDHCI_QUIRK2_BROKEN_DDR50 = 0x40
options sdhci debug_quirks2=0x40
MODPROBE

  # Install systemd service to load mv88e6xxx after boot
  cat > "${ROOTFS}/etc/systemd/system/mv88e6xxx-load.service" <<'SERVICE'
[Unit]
Description=Load Marvell DSA switch driver after boot
DefaultDependencies=no
After=local-fs.target systemd-modules-load.service
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/modprobe dsa_core
ExecStart=/sbin/modprobe mv88e6xxx
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE
  chroot "${ROOTFS}" systemctl enable mv88e6xxx-load.service 2>/dev/null || true

  # Regénérer initramfs avec les modules eMMC et blacklist
  log "Regénération initramfs..."
  chroot "${ROOTFS}" update-initramfs -u 2>/dev/null || warn "update-initramfs partiel"
  ok "Hooks initramfs installés (sdhci-xenon + mv88e6xxx blacklist + delayed load service)"
fi

# ── Étape 4 : firstboot.sh ────────────────────────────────────────
log "4/7 Installation firstboot..."
install -m 755 "${SCRIPT_DIR}/firstboot.sh" "${ROOTFS}/usr/bin/secubox-firstboot"

# Unit systemd firstboot (one-shot)
cat > "${ROOTFS}/etc/systemd/system/secubox-firstboot.service" <<'EOF'
[Unit]
Description=SecuBox First Boot Initialization
After=network.target
ConditionPathExists=!/var/lib/secubox/.firstboot_done

[Service]
Type=oneshot
ExecStart=/usr/bin/secubox-firstboot
ExecStartPost=/usr/bin/touch /var/lib/secubox/.firstboot_done
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

chroot "${ROOTFS}" systemctl enable secubox-firstboot.service
ok "firstboot.sh installé"

# ── Pre-generate SSL certificates for nginx ─────────────────────────
# (firstboot will regenerate on first boot, but nginx needs certs to start)
# Generate certs on HOST (chroot may lack /dev/urandom)
log "Pre-generating SSL certificates..."
mkdir -p "${ROOTFS}/etc/secubox/tls"
mkdir -p "${ROOTFS}/run/secubox"
mkdir -p "${ROOTFS}/var/lib/secubox"

openssl req -x509 -newkey rsa:2048 -days 365 \
  -keyout "${ROOTFS}/etc/secubox/tls/key.pem" \
  -out "${ROOTFS}/etc/secubox/tls/cert.pem" \
  -nodes -subj "/CN=secubox/O=CyberMind SecuBox/C=FR" \
  -addext "subjectAltName=DNS:localhost,DNS:secubox.local,IP:127.0.0.1,IP:192.168.1.1" \
  2>/dev/null

if [[ -f "${ROOTFS}/etc/secubox/tls/cert.pem" ]]; then
  chmod 640 "${ROOTFS}/etc/secubox/tls/key.pem"
  chmod 644 "${ROOTFS}/etc/secubox/tls/cert.pem"
  ok "SSL certificates pre-generated"
else
  warn "SSL cert generation failed - nginx may not start"
fi

# ── SecuBox Profile and Status Scripts ─────────────────────────────
log "Installing SecuBox profile scripts..."

# Profile.d script for login status display
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

# SecuBox help command
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

# SecuBox logs command
cat > "${ROOTFS}/usr/bin/secubox-logs" <<'LOGS_CMD'
#!/bin/bash
# SecuBox Live Security Logs
echo "📋 SecuBox Security Logs (Ctrl+C to exit)"
echo "─────────────────────────────────────────"
journalctl -f -u 'secubox-*' -u crowdsec -u suricata -u nginx --no-pager 2>/dev/null || \
journalctl -f --no-pager
LOGS_CMD
chmod +x "${ROOTFS}/usr/bin/secubox-logs"

# SecuBox status command
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

# SecuBox password reset command
cat > "${ROOTFS}/usr/bin/secubox-passwd" <<'PASSWD_SCRIPT'
#!/bin/bash
# SecuBox Password Reset
set -e
USERS_FILE="/etc/secubox/users.json"
CONF_FILE="/etc/secubox/secubox.conf"
echo "SecuBox Password Reset"
[[ $EUID -ne 0 ]] && echo "Error: Run as root" && exit 1
read -sp "New password for admin: " NEW_PASS && echo
read -sp "Confirm password: " CONFIRM && echo
[[ "$NEW_PASS" != "$CONFIRM" ]] && echo "Passwords don't match" && exit 1
[[ ${#NEW_PASS} -lt 4 ]] && echo "Password too short" && exit 1
NEW_HASH=$(echo -n "$NEW_PASS" | sha256sum | cut -d' ' -f1)
if [[ -f "$USERS_FILE" ]]; then
    sed -i "s/\"password_hash\": \"[^\"]*\"/\"password_hash\": \"${NEW_HASH}\"/g" "$USERS_FILE"
    echo "Updated users.json"
fi
if [[ -f "$CONF_FILE" ]]; then
    sed -i "s/^password = .*/password = \"${NEW_PASS}\"/" "$CONF_FILE"
    echo "Updated secubox.conf"
fi
systemctl restart secubox-portal secubox-hub 2>/dev/null || true
echo "Password reset complete!"
PASSWD_SCRIPT
chmod +x "${ROOTFS}/usr/bin/secubox-passwd"

ok "SecuBox profile scripts installed"

# ── CRT-Style Boot Banners ─────────────────────────────────────────
log "Creating boot banners..."

# Pre-login banner (/etc/issue)
printf '%b' "\e[38;5;214m
   ██████ ███████  ██████ ██    ██ ██████   ██████  ██   ██
  ██      ██      ██      ██    ██ ██   ██ ██    ██  ██ ██
  ███████ █████   ██      ██    ██ ██████  ██    ██   ███
       ██ ██      ██      ██    ██ ██   ██ ██    ██  ██ ██
  ███████ ███████  ██████  ██████  ██████   ██████  ██   ██
\e[0m
\e[38;5;45m  ⚡ CyberMind Security Platform\e[0m  \e[38;5;82mv${SECUBOX_VERSION}\e[0m  \e[38;5;242m\\\\l @ \\\\n\e[0m
\e[38;5;242m  Build: ${BUILD_TIMESTAMP}\e[0m

\e[38;5;250m  🔐 Default: \e[38;5;214mroot\e[38;5;250m / \e[38;5;214msecubox\e[0m
\e[38;5;250m  🌐 Web UI: \e[38;5;45mhttps://<IP>:9443\e[0m
\e[38;5;250m  📡 SSH:    \e[38;5;45mport 22\e[0m

\e[38;5;242m─────────────────────────────────────────────────────────────\e[0m

" > "${ROOTFS}/etc/issue"

# Post-login MOTD
printf '%b' "\e[38;5;214m
  ╔═══════════════════════════════════════════════════════════════╗
  ║\e[38;5;45m   ███████╗███████╗ ██████╗██╗   ██╗██████╗  ██████╗ ██╗  ██╗  \e[38;5;214m║
  ║\e[38;5;45m   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔═══██╗╚██╗██╔╝  \e[38;5;214m║
  ║\e[38;5;45m   ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║ ╚███╔╝   \e[38;5;214m║
  ║\e[38;5;45m   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║ ██╔██╗   \e[38;5;214m║
  ║\e[38;5;45m   ███████║███████╗╚██████╗╚██████╔╝██████╔╝╚██████╔╝██╔╝ ██╗  \e[38;5;214m║
  ║\e[38;5;45m   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝  \e[38;5;214m║
  ║\e[38;5;82m            ⚡ eMMC / SD IMAGE ⚡  v${SECUBOX_VERSION}               \e[38;5;214m║
  ╚═══════════════════════════════════════════════════════════════╝\e[0m

\e[38;5;242m  Build: ${BUILD_TIMESTAMP}\e[0m

\e[38;5;250m  🌐 Web UI:     \e[38;5;45mhttps://<IP>:9443\e[0m
\e[38;5;250m  🔐 Credentials: \e[38;5;214mroot\e[38;5;250m / \e[38;5;214msecubox\e[0m
\e[38;5;250m  📖 Docs:       \e[38;5;45mhttps://secubox.in/docs\e[0m

\e[38;5;242m  Type \e[38;5;82msecubox-status\e[38;5;242m for system overview\e[0m

" > "${ROOTFS}/etc/motd"

ok "Boot banners installed"

# ── Étape 5 : Configuration bootloader ────────────────────────────
log "5/7 Configuration bootloader..."

if [[ $IS_X64 -eq 1 ]] || [[ "${BOARD}" == "vm-arm64" ]]; then
  # GRUB EFI pour x64 ou arm64 VM
  cat > "${ROOTFS}/etc/default/grub" <<'EOF'
GRUB_DEFAULT=0
GRUB_TIMEOUT=3
GRUB_DISTRIBUTOR="SecuBox"
GRUB_CMDLINE_LINUX_DEFAULT="quiet net.ifnames=1"
GRUB_CMDLINE_LINUX=""
GRUB_TERMINAL=console
EOF
  ok "GRUB configuré"
else
  # U-Boot pour ARM hardware
  warn "U-Boot : kernel/DTB à placer dans board/${BOARD}/kernel/"
fi

# ── Étape 6 : Construction de l'image ─────────────────────────────
log "6/7 Construction image GPT ${IMG_SIZE}..."

# Démonter les filesystems avant création image
umount -lf "${ROOTFS}/proc" 2>/dev/null || true
umount -lf "${ROOTFS}/sys"  2>/dev/null || true
umount -lf "${ROOTFS}/dev"  2>/dev/null || true

# Créer fichier image
fallocate -l "${IMG_SIZE}" "${IMG_FILE}"

if [[ $IS_X64 -eq 1 ]] || [[ "${BOARD}" == "vm-arm64" ]]; then
  # GPT + ESP pour UEFI (x64 ou arm64 VM)
  parted -s "${IMG_FILE}" \
    mklabel gpt \
    mkpart ESP  fat32  1MiB   513MiB \
    mkpart ROOT ext4   513MiB 3073MiB \
    mkpart DATA ext4   3073MiB 100% \
    set 1 esp on \
    set 1 boot on
else
  # GPT pour ARM hardware (boot + rootfs + data)
  parted -s "${IMG_FILE}" \
    mklabel gpt \
    mkpart boot fat32  2MiB   258MiB \
    mkpart ROOT ext4   258MiB 2818MiB \
    mkpart DATA ext4   2818MiB 100% \
    set 1 boot on
fi

# Associer loop device
LOOP=$(losetup -f --show -P "${IMG_FILE}")
log "  loop device: ${LOOP}"

# Formater partitions
if [[ $IS_X64 -eq 1 ]] || [[ "${BOARD}" == "vm-arm64" ]]; then
  mkfs.fat  -F32 -n "ESP"    "${LOOP}p1"
else
  mkfs.fat  -F32 -n "boot"   "${LOOP}p1"
fi
mkfs.ext4 -L "rootfs" -q "${LOOP}p2"
mkfs.ext4 -L "data"   -q "${LOOP}p3"

# Copier rootfs
MNT="${WORK_DIR}/mnt"
mkdir -p "${MNT}"
mount "${LOOP}p2" "${MNT}"

if [[ $IS_X64 -eq 1 ]] || [[ "${BOARD}" == "vm-arm64" ]]; then
  mkdir -p "${MNT}/boot/efi" "${MNT}/data"
  mount "${LOOP}p1" "${MNT}/boot/efi"
else
  mkdir -p "${MNT}/boot" "${MNT}/data"
  mount "${LOOP}p1" "${MNT}/boot"
fi

rsync -ax --exclude={"/proc/*","/sys/*","/dev/*","/run/*","/tmp/*"} \
  "${ROOTFS}/" "${MNT}/"

# Installation GRUB pour x64 ou arm64 VM
if [[ $IS_X64 -eq 1 ]] || [[ "${BOARD}" == "vm-arm64" ]]; then
  # Monter les fs pour GRUB install
  mount --bind /dev  "${MNT}/dev"
  mount --bind /proc "${MNT}/proc"
  mount --bind /sys  "${MNT}/sys"

  if [[ $IS_X64 -eq 1 ]]; then
    GRUB_TARGET="x86_64-efi"
  else
    GRUB_TARGET="arm64-efi"
  fi

  chroot "${MNT}" grub-install --target=${GRUB_TARGET} --efi-directory=/boot/efi \
    --bootloader-id=secubox --no-nvram --removable 2>/dev/null || warn "grub-install partiel"
  chroot "${MNT}" update-grub 2>/dev/null || warn "update-grub partiel"

  # Create EFI grub.cfg that chains to main config (fix for VirtualBox/OVMF)
  ROOT_UUID=$(chroot "${MNT}" blkid -s UUID -o value /dev/disk/by-label/rootfs 2>/dev/null || \
              grep -oP 'root=UUID=\K[^ ]+' "${MNT}/boot/grub/grub.cfg" | head -1)
  if [[ -n "$ROOT_UUID" ]]; then
    cat > "${MNT}/boot/efi/EFI/BOOT/grub.cfg" << EOFGRUB
# SecuBox GRUB EFI config - search and chain to main config
search --no-floppy --fs-uuid --set=root ${ROOT_UUID}
set prefix=(\$root)/boot/grub
configfile \$prefix/grub.cfg
EOFGRUB
    ok "EFI grub.cfg créé (UUID: ${ROOT_UUID})"
  else
    warn "Impossible de créer EFI grub.cfg - UUID rootfs non trouvé"
  fi

  umount -lf "${MNT}/sys"  2>/dev/null || true
  umount -lf "${MNT}/proc" 2>/dev/null || true
  umount -lf "${MNT}/dev"  2>/dev/null || true
else
  # ARM physique : copier kernel + DTB depuis linux-image-arm64
  log "Configuration boot U-Boot pour ${BOARD}..."

  # Copier le kernel (vmlinuz → Image pour U-Boot)
  VMLINUZ=$(ls "${MNT}/boot/vmlinuz-"* 2>/dev/null | head -1)
  if [[ -n "$VMLINUZ" ]]; then
    cp "$VMLINUZ" "${MNT}/boot/Image"
    ok "Kernel copié : $(basename $VMLINUZ) → Image"
  else
    warn "Kernel vmlinuz non trouvé dans /boot"
  fi

  # Copier l'initramfs (requis pour sdhci-xenon sur eMMC)
  INITRD=$(ls "${MNT}/boot/initrd.img-"* 2>/dev/null | head -1)
  if [[ -n "$INITRD" ]]; then
    cp "$INITRD" "${MNT}/boot/initrd.img"
    ok "Initramfs copié : $(basename $INITRD) → initrd.img"
  else
    warn "Initramfs non trouvé dans /boot"
  fi

  # Copier le DTB depuis /usr/lib/linux-image-*/
  DTB_DIR=$(ls -d "${MNT}/usr/lib/linux-image-"*/ 2>/dev/null | head -1)
  if [[ -d "$DTB_DIR" ]]; then
    mkdir -p "${MNT}/boot/dtbs"
    # Copier les DTBs Marvell (Armada)
    if [[ -d "${DTB_DIR}/marvell" ]]; then
      cp -r "${DTB_DIR}/marvell" "${MNT}/boot/dtbs/"
      ok "DTBs Marvell copiés vers /boot/dtbs/marvell/"
    fi
  else
    warn "Répertoire DTB non trouvé dans /usr/lib/linux-image-*/"
  fi

  # Créer extlinux.conf pour U-Boot distroboot
  mkdir -p "${MNT}/boot/extlinux"
  # Default to eMMC variant DTB for boards with eMMC
  KERNEL_DTS="${KERNEL_DTS:-armada-3720-espressobin-v7-emmc}"

  # Use LABEL for reliable root identification (device names change based on connected storage)
  ROOT_DEV="LABEL=rootfs"

  cat > "${MNT}/boot/extlinux/extlinux.conf" <<EXTLINUX
DEFAULT secubox
TIMEOUT 30
PROMPT 1

LABEL secubox
    KERNEL /Image
    INITRD /initrd.img
    FDT /dtbs/marvell/${KERNEL_DTS}.dtb
    APPEND root=${ROOT_DEV} rootfstype=ext4 rootwait rootdelay=5 console=ttyMV0,115200 net.ifnames=0 modprobe.blacklist=mv88e6xxx,dsa_core sdhci.debug_quirks2=0x40
EXTLINUX
  ok "extlinux.conf créé pour ${KERNEL_DTS} (root=${ROOT_DEV})"

  # Créer boot.scr pour U-Boot (alternative à extlinux)
  # Utiliser le boot.cmd spécifique au board s'il existe
  BOARD_BOOTCMD="${SCRIPT_DIR}/../board/${BOARD}/boot.cmd"
  if [[ -f "$BOARD_BOOTCMD" ]]; then
    log "Utilisation du boot.cmd spécifique au board ${BOARD}"
    cp "$BOARD_BOOTCMD" "${MNT}/boot/boot.cmd"
  else
    # Fallback: générer un boot.cmd générique
    cat > "${MNT}/boot/boot.cmd" <<'BOOTCMD'
# SecuBox U-Boot boot script
# Auto-generated fallback — board-specific boot.cmd recommended

echo "============================================"
echo "SecuBox Boot Script"
echo "============================================"

# Detect boot device from U-Boot environment
if test -n "${devtype}" -a -n "${devnum}"; then
    echo "Boot device from env: ${devtype} ${devnum}"
    setenv bootdev "${devnum}"
else
    setenv bootdev 0
    echo "Using mmc 0 as boot device"
fi

setenv bootpart "mmc ${bootdev}:1"
# Linux eMMC is typically mmcblk0 regardless of U-Boot device number
setenv rootpart "/dev/mmcblk0p2"

echo "Boot partition: ${bootpart}"
echo "Root partition: ${rootpart}"

# Load kernel
echo "Loading kernel from ${bootpart}..."
load ${bootpart} ${kernel_addr_r} Image

# Load initramfs (required for eMMC support)
echo "Loading initramfs..."
if load ${bootpart} ${ramdisk_addr_r} initrd.img; then
    echo "Initramfs loaded OK"
    setenv initrd_size ${filesize}
    setenv use_initrd 1
else
    echo "WARNING: No initramfs found"
    setenv use_initrd 0
fi

# Load DTB
echo "Loading device tree..."
BOOTCMD

    # Ajouter le DTB spécifique au board
    cat >> "${MNT}/boot/boot.cmd" <<BOOTCMD_DTB
if load \${bootpart} \${fdt_addr_r} dtbs/marvell/${KERNEL_DTS}.dtb; then
    echo "DTB loaded: ${KERNEL_DTS}.dtb"
else
    echo "ERROR: Failed to load DTB ${KERNEL_DTS}.dtb"
fi
BOOTCMD_DTB

    cat >> "${MNT}/boot/boot.cmd" <<'BOOTCMD_END'

# Set boot args
# modprobe.blacklist: prevent mv88e6xxx DSA driver from loading during initramfs
# sdhci.debug_quirks2=0x40: fix xenon-sdhci DDR timing issues
setenv bootargs "root=${rootpart} rootfstype=ext4 rootwait rootdelay=5 console=ttyMV0,115200 net.ifnames=0 modprobe.blacklist=mv88e6xxx,dsa_core sdhci.debug_quirks2=0x40"

echo "Boot args: ${bootargs}"
echo "============================================"
echo "Booting SecuBox..."
echo "============================================"

if test "${use_initrd}" = "1"; then
    booti ${kernel_addr_r} ${ramdisk_addr_r}:${initrd_size} ${fdt_addr_r}
else
    booti ${kernel_addr_r} - ${fdt_addr_r}
fi
BOOTCMD_END
  fi

  # Compiler le bootscript si mkimage est disponible
  if command -v mkimage >/dev/null 2>&1; then
    mkimage -C none -A arm64 -T script -d "${MNT}/boot/boot.cmd" "${MNT}/boot/boot.scr" >/dev/null
    ok "boot.scr créé (U-Boot bootscript)"
  else
    warn "mkimage non disponible — boot.scr non généré (installer u-boot-tools)"
  fi
fi

# Démonter
if [[ $IS_X64 -eq 1 ]] || [[ "${BOARD}" == "vm-arm64" ]]; then
  umount "${MNT}/boot/efi"
else
  umount "${MNT}/boot"
fi
umount "${MNT}"
losetup -d "${LOOP}"
LOOP=""
ok "Image construite : ${IMG_FILE}"

# ── Étape 7 : Compression + conversion VDI ────────────────────────
log "7/7 Post-traitement..."

# Conversion VDI pour VirtualBox (x64 seulement)
if [[ $IS_X64 -eq 1 ]] && [[ $CONVERT_VDI -eq 1 ]]; then
  VDI_FILE="${OUT_DIR}/secubox-${BOARD}-${SUITE}.vdi"
  log "  Conversion en VDI..."
  if qemu-img convert -f raw -O vdi "${IMG_FILE}" "${VDI_FILE}"; then
    ok "VDI créé : ${VDI_FILE}"
  else
    err "Échec conversion VDI"
  fi
fi

# Conversion QCOW2 pour QEMU (arm64 VM)
if [[ "${BOARD}" == "vm-arm64" ]]; then
  QCOW2_FILE="${OUT_DIR}/secubox-${BOARD}-${SUITE}.qcow2"
  log "  Conversion en QCOW2..."
  qemu-img convert -f raw -O qcow2 "${IMG_FILE}" "${QCOW2_FILE}"
  ok "QCOW2 créé : ${QCOW2_FILE}"
fi

# Compression
log "  Compression gzip..."
gzip -9 -f "${IMG_FILE}"
IMG_GZ="${IMG_FILE}.gz"
sha256sum "${IMG_GZ}" > "${IMG_GZ}.sha256"

ok "Livrable : ${IMG_GZ} ($(du -sh "${IMG_GZ}" | cut -f1))"

echo ""
echo -e "${GOLD}${BOLD}════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Image SecuBox-${BOARD} prête !${NC}"
echo ""
if [[ $IS_X64 -eq 1 ]]; then
  echo -e "  VirtualBox : Importer le .vdi ou décompresser le .img"
  echo -e "  QEMU       : qemu-system-x86_64 -drive file=${IMG_FILE},format=raw -enable-kvm"
  if [[ $CONVERT_VDI -eq 1 ]]; then
    echo -e "  VDI        : ${VDI_FILE}"
  fi
elif [[ "${BOARD}" == "vm-arm64" ]]; then
  echo -e "  QEMU arm64 :"
  echo -e "    qemu-system-aarch64 -M virt -cpu cortex-a72 -m 2048 -smp 2 \\"
  echo -e "      -bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \\"
  echo -e "      -drive file=${QCOW2_FILE},format=qcow2 \\"
  echo -e "      -device virtio-net-pci,netdev=net0 -netdev user,id=net0,hostfwd=tcp::2222-:22 \\"
  echo -e "      -nographic"
  echo -e "  QCOW2      : ${QCOW2_FILE}"
else
  echo -e "  Flasher : zcat ${IMG_GZ} | dd of=/dev/mmcblk0 bs=4M status=progress"
fi
echo -e "${GOLD}${BOLD}════════════════════════════════════════════${NC}"
