#!/bin/bash
# SecuBox MOCHAbin Kernel Build Script
# Builds kernel 6.6.x LTS with LED module support

set -euo pipefail

KERNEL_VERSION="${KERNEL_VERSION:-6.6.137}"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz"
BUILD_DIR="${BUILD_DIR:-/tmp/secubox-kernel-build}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FRAGMENT="$REPO_DIR/board/mochabin/kernel/config-6.12-openwrt-merged.fragment"
# Additional fragments merged on top (in order). Last write wins.
CONFIG_FRAGMENT_ZRAM="$REPO_DIR/board/mochabin/kernel/config-6.12.85-secubox-zram.fragment"
PATCHES_DIR="$SCRIPT_DIR/patches"
JOBS="${JOBS:-$(nproc)}"
OUTPUT_DIR="${OUTPUT_DIR:-$BUILD_DIR/output}"

log() { echo "[$(date '+%H:%M:%S')] $1"; }
error() { echo "[ERROR] $1" >&2; exit 1; }

check_deps() {
    log "Checking dependencies..."
    sudo apt update && sudo apt install -y \
        gcc-aarch64-linux-gnu make bc flex bison \
        libssl-dev libelf-dev wget xz-utils
}

download_kernel() {
    log "Downloading kernel $KERNEL_VERSION..."
    mkdir -p "$BUILD_DIR" && cd "$BUILD_DIR"
    [ -f "linux-${KERNEL_VERSION}.tar.xz" ] || wget -c "$KERNEL_URL"
    [ -d "linux-${KERNEL_VERSION}" ] || tar xf "linux-${KERNEL_VERSION}.tar.xz"
}

apply_patches() {
    log "Applying patches..."
    cd "$BUILD_DIR/linux-${KERNEL_VERSION}"
    for patch in "$PATCHES_DIR"/*.patch; do
        [ -f "$patch" ] && patch -p1 -N < "$patch" || true
    done
}

configure_kernel() {
    log "Configuring kernel..."
    cd "$BUILD_DIR/linux-${KERNEL_VERSION}"
    make ARCH=arm64 defconfig
    scripts/kconfig/merge_config.sh -m .config "$CONFIG_FRAGMENT" "$CONFIG_FRAGMENT_ZRAM"
    make ARCH=arm64 olddefconfig
    grep -q "CONFIG_LEDS_IS31FL319X=m" .config && log "✓ LED as module" || log "⚠ LED not module"
    grep -q "CONFIG_ZRAM=m" .config && log "✓ ZRAM as module" || log "⚠ ZRAM missing"
    grep -q "CONFIG_ZRAM_DEF_COMP=\"zstd\"" .config && log "✓ ZRAM default zstd" || log "⚠ ZRAM compressor not zstd"
}

build_kernel() {
    log "Building kernel..."
    cd "$BUILD_DIR/linux-${KERNEL_VERSION}"
    make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j"$JOBS" Image modules dtbs
}

install_output() {
    log "Installing output..."
    mkdir -p "$OUTPUT_DIR"
    cd "$BUILD_DIR/linux-${KERNEL_VERSION}"
    cp arch/arm64/boot/Image "$OUTPUT_DIR/Image-${KERNEL_VERSION}-secubox"
    cp arch/arm64/boot/dts/marvell/armada-7040-mochabin.dtb "$OUTPUT_DIR/"
    make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- INSTALL_MOD_PATH="$OUTPUT_DIR/modules" modules_install
    log "Output: $OUTPUT_DIR"
    ls -la "$OUTPUT_DIR/"
}

deploy_to_device() {
    local HOST="${1:-root@192.168.1.200}"
    log "Deploying to $HOST..."

    # Deploy kernel and DTB
    scp "$OUTPUT_DIR/Image-${KERNEL_VERSION}-secubox" "$HOST:/boot/"
    scp "$OUTPUT_DIR/armada-7040-mochabin.dtb" "$HOST:/boot/"

    # SAFE module deployment - don't overwrite /lib symlink!
    # Create tarball with correct structure for /lib/modules/ extraction
    log "Creating safe modules tarball..."
    cd "$OUTPUT_DIR/modules/lib/modules"
    tar czf "/tmp/modules-${KERNEL_VERSION}.tar.gz" "${KERNEL_VERSION}"

    # Deploy and extract safely
    scp "/tmp/modules-${KERNEL_VERSION}.tar.gz" "$HOST:/tmp/"
    ssh "$HOST" "mkdir -p /lib/modules && cd /lib/modules && tar xzf /tmp/modules-${KERNEL_VERSION}.tar.gz && depmod -a ${KERNEL_VERSION} || true"

    log "Deployed! Add boot entry and reboot."
}

case "${1:-build}" in
    build) check_deps; download_kernel; apply_patches; configure_kernel; build_kernel; install_output ;;
    deps) check_deps ;;
    config) configure_kernel ;;
    clean) rm -rf "$BUILD_DIR" ;;
    *) echo "Usage: $0 {build|deps|config|clean}" ;;
esac
