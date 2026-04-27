#!/usr/bin/env bash
# SecuBox AMD64 Live Rootfs Builder
# Creates Debian bookworm AMD64 rootfs with SecuBox packages
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

OUTPUT_DIR=""
MINIMAL=false
INCLUDE_DESKTOP=false
MIRROR="http://deb.debian.org/debian"
SECUBOX_REPO="https://apt.secubox.in"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Build SecuBox AMD64 rootfs

Options:
    -o, --output DIR        Output directory for rootfs
    --minimal               Minimal installation (no SecuBox packages)
    --desktop               Include desktop environment
    --mirror URL            Debian mirror (default: $MIRROR)
    -h, --help              Show this help
EOF
    exit 0
}

log() { echo "[$(date '+%H:%M:%S')] $*"; }
err() { echo "[ERROR] $*" >&2; exit 1; }

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
            --minimal) MINIMAL=true; shift ;;
            --desktop) INCLUDE_DESKTOP=true; shift ;;
            --mirror) MIRROR="$2"; shift 2 ;;
            -h|--help) usage ;;
            *) err "Unknown option: $1" ;;
        esac
    done

    if [[ -z "$OUTPUT_DIR" ]]; then
        err "Output directory required (-o)"
    fi
}

check_deps() {
    local deps=(debootstrap chroot)
    for cmd in "${deps[@]}"; do
        command -v "$cmd" &>/dev/null || err "Missing: $cmd"
    done
    [[ $EUID -eq 0 ]] || err "Must run as root"
}

bootstrap_rootfs() {
    log "Bootstrapping Debian bookworm AMD64..."

    mkdir -p "$OUTPUT_DIR"

    debootstrap --arch=amd64 \
        --include=systemd,systemd-sysv,dbus,locales,apt-transport-https,ca-certificates,curl,gnupg \
        bookworm "$OUTPUT_DIR" "$MIRROR"
}

configure_rootfs() {
    log "Configuring rootfs..."

    # Set hostname
    echo "secubox-amd64" > "$OUTPUT_DIR/etc/hostname"

    # Configure hosts
    cat > "$OUTPUT_DIR/etc/hosts" <<EOF
127.0.0.1   localhost
127.0.1.1   secubox-amd64

::1         localhost ip6-localhost ip6-loopback
ff02::1     ip6-allnodes
ff02::2     ip6-allrouters
EOF

    # Configure locales
    echo "en_US.UTF-8 UTF-8" > "$OUTPUT_DIR/etc/locale.gen"
    chroot "$OUTPUT_DIR" locale-gen

    # Configure timezone
    ln -sf /usr/share/zoneinfo/UTC "$OUTPUT_DIR/etc/localtime"

    # Configure apt sources
    cat > "$OUTPUT_DIR/etc/apt/sources.list" <<EOF
deb $MIRROR bookworm main contrib non-free non-free-firmware
deb $MIRROR bookworm-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
EOF

    # Configure network
    cat > "$OUTPUT_DIR/etc/network/interfaces" <<EOF
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF

    # Create fstab
    cat > "$OUTPUT_DIR/etc/fstab" <<EOF
# <file system>  <mount point>  <type>  <options>  <dump>  <pass>
LABEL=secubox-amd64  /  ext4  errors=remount-ro  0  1
LABEL=SECUBOX-EFI    /boot/efi  vfat  umask=0077  0  1
EOF
}

install_kernel() {
    log "Installing Linux kernel..."

    chroot "$OUTPUT_DIR" apt-get update
    chroot "$OUTPUT_DIR" apt-get install -y \
        linux-image-amd64 \
        linux-headers-amd64 \
        firmware-linux \
        firmware-linux-nonfree
}

install_base_packages() {
    log "Installing base packages..."

    chroot "$OUTPUT_DIR" apt-get install -y \
        openssh-server \
        sudo \
        vim \
        nano \
        htop \
        tmux \
        git \
        wget \
        net-tools \
        iproute2 \
        iputils-ping \
        dnsutils \
        tcpdump \
        iptables \
        nftables \
        nginx \
        python3 \
        python3-pip \
        python3-venv \
        python3-uvicorn \
        python3-fastapi \
        python3-jose \
        python3-httpx \
        python3-psutil \
        python3-jinja2
}

add_secubox_repo() {
    if [[ "$MINIMAL" == "true" ]]; then
        log "Skipping SecuBox repo (minimal mode)"
        return
    fi

    log "Adding SecuBox repository..."

    # Add SecuBox GPG key
    mkdir -p "$OUTPUT_DIR/etc/apt/keyrings"
    curl -fsSL "${SECUBOX_REPO}/gpg.key" | gpg --dearmor -o "$OUTPUT_DIR/etc/apt/keyrings/secubox.gpg" 2>/dev/null || true

    # Add SecuBox repo
    cat > "$OUTPUT_DIR/etc/apt/sources.list.d/secubox.list" <<EOF
deb [signed-by=/etc/apt/keyrings/secubox.gpg] ${SECUBOX_REPO} bookworm main
EOF

    chroot "$OUTPUT_DIR" apt-get update || true
}

install_secubox_packages() {
    if [[ "$MINIMAL" == "true" ]]; then
        log "Skipping SecuBox packages (minimal mode)"
        return
    fi

    log "Installing SecuBox packages..."

    # Install core SecuBox packages
    chroot "$OUTPUT_DIR" apt-get install -y \
        secubox-core \
        secubox-hub \
        secubox-haproxy \
        secubox-crowdsec \
        secubox-system \
        secubox-hardening \
        secubox-ipblock \
        || log "WARNING: Some SecuBox packages failed to install"
}

install_desktop() {
    if [[ "$INCLUDE_DESKTOP" != "true" ]]; then
        return
    fi

    log "Installing desktop environment..."

    chroot "$OUTPUT_DIR" apt-get install -y \
        xorg \
        xfce4 \
        xfce4-terminal \
        lightdm \
        firefox-esr \
        || log "WARNING: Desktop installation incomplete"
}

setup_users() {
    log "Setting up users..."

    # Set root password
    echo "root:secubox" | chroot "$OUTPUT_DIR" chpasswd

    # Create secubox user
    chroot "$OUTPUT_DIR" useradd -m -s /bin/bash -G sudo secubox || true
    echo "secubox:secubox" | chroot "$OUTPUT_DIR" chpasswd

    # Allow sudo without password for secubox
    echo "secubox ALL=(ALL) NOPASSWD:ALL" > "$OUTPUT_DIR/etc/sudoers.d/secubox"
    chmod 440 "$OUTPUT_DIR/etc/sudoers.d/secubox"
}

setup_boot() {
    log "Setting up boot configuration..."

    # Install GRUB for UEFI
    chroot "$OUTPUT_DIR" apt-get install -y grub-efi-amd64 || true

    # Create boot directory structure
    mkdir -p "$OUTPUT_DIR/boot/efi"
}

setup_secubox_branding() {
    log "Adding SecuBox branding..."

    # MOTD
    cat > "$OUTPUT_DIR/etc/motd" <<'MOTD'

   ██████ ███████  ██████ ██    ██ ██████   ██████  ██   ██
  ██      ██      ██      ██    ██ ██   ██ ██    ██  ██ ██
  ███████ █████   ██      ██    ██ ██████  ██    ██   ███
       ██ ██      ██      ██    ██ ██   ██ ██    ██  ██ ██
  ███████ ███████  ██████  ██████  ██████   ██████  ██   ██

  SecuBox AMD64 Live System
  https://secubox.in

MOTD

    # Issue
    cat > "$OUTPUT_DIR/etc/issue" <<'ISSUE'
SecuBox AMD64 \n \l

ISSUE
}

cleanup_rootfs() {
    log "Cleaning up rootfs..."

    chroot "$OUTPUT_DIR" apt-get clean
    rm -rf "$OUTPUT_DIR/var/lib/apt/lists/"*
    rm -rf "$OUTPUT_DIR/tmp/"*
    rm -f "$OUTPUT_DIR/var/log/"*.log
}

main() {
    parse_args "$@"
    check_deps

    log "Building SecuBox AMD64 Rootfs"
    log "Output: $OUTPUT_DIR"
    log "Minimal: $MINIMAL"

    bootstrap_rootfs
    configure_rootfs
    install_kernel
    install_base_packages
    add_secubox_repo
    install_secubox_packages
    install_desktop
    setup_users
    setup_boot
    setup_secubox_branding
    cleanup_rootfs

    log "============================================"
    log "AMD64 Rootfs Complete: $OUTPUT_DIR"
    log "============================================"
}

main "$@"
