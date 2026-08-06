#!/bin/bash
# scripts/build-kernel-local.sh — local kernel cross-build for fast iteration
#
# Replicates .github/workflows/build-kernel.yml step-by-step on the dev box,
# so we don't pay 20 min/round-trip on GitHub Actions.
#
# Usage:
#   bash scripts/build-kernel-local.sh                   # default 6.12.85, 2secubox
#   bash scripts/build-kernel-local.sh 6.12.85 3secubox  # override
#
# Output:
#   .debs land in /tmp/secubox-kernel-build/ (linux-image-*, linux-headers-*).
#
# Iteration tip: the tarball + olddefconfig are slow; once the build tree exists,
# subsequent runs reuse it (skip download + re-run merge from scratch). To force
# a clean rebuild from scratch, `rm -rf /tmp/secubox-kernel-build`.

set -euo pipefail

KERNEL_VERSION="${1:-6.12.85}"
REVISION="${2:-2secubox}"
KDEB_PKGVERSION="${KERNEL_VERSION}-${REVISION}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_ROOT="/tmp/secubox-kernel-build"
SRC_DIR="$BUILD_ROOT/linux-${KERNEL_VERSION}"

export DEBFULLNAME="${DEBFULLNAME:-SecuBox Builder}"
export DEBEMAIL="${DEBEMAIL:-devel@cybermind.fr}"

log() { printf '\033[1;36m[%s] %s\033[0m\n' "$(date '+%H:%M:%S')" "$*"; }
fail() { printf '\033[1;31m[%s] FAIL: %s\033[0m\n' "$(date '+%H:%M:%S')" "$*" >&2; exit 1; }

# ── 1. download upstream tarball if absent ──────────────────────────────────
mkdir -p "$BUILD_ROOT"
cd "$BUILD_ROOT"
if [ ! -d "$SRC_DIR" ]; then
    log "downloading linux-${KERNEL_VERSION}.tar.xz"
    MAJOR="$(echo "$KERNEL_VERSION" | cut -d. -f1)"
    wget -q "https://cdn.kernel.org/pub/linux/kernel/v${MAJOR}.x/linux-${KERNEL_VERSION}.tar.xz"
    log "extracting"
    tar xf "linux-${KERNEL_VERSION}.tar.xz"
else
    log "src tree already at $SRC_DIR — reusing (rm -rf $BUILD_ROOT to force clean)"
fi
cd "$SRC_DIR"

# ── 2. apply SecuBox patches ────────────────────────────────────────────────
PATCH_DIR="$REPO_ROOT/kernel-build/patches"
if [ -d "$PATCH_DIR" ]; then
    for p in "$PATCH_DIR"/*.patch; do
        [ -f "$p" ] || continue
        log "applying patch $(basename "$p")"
        patch -p1 -N --dry-run < "$p" >/dev/null 2>&1 \
            && patch -p1 -N < "$p" >/dev/null \
            || log "  (already applied or fails dry-run — skipping)"
    done
fi

# ── 3. defconfig + merge config fragments ───────────────────────────────────
log "make ARCH=arm64 defconfig"
make ARCH=arm64 defconfig >/dev/null

log "merge_config.sh -m .config + fragments"
scripts/kconfig/merge_config.sh -m .config \
    "$REPO_ROOT/board/mochabin/kernel/config-6.12-openwrt-merged.fragment" \
    "$REPO_ROOT/board/mochabin/kernel/config-6.12.85-secubox-zram.fragment" \
    "$REPO_ROOT/board/mochabin/kernel/config-6.12.85-secubox-filesystems.fragment" \
    >/dev/null

# ── 4. enable supporting non-choice symbols ─────────────────────────────────
log "scripts/config: enable ZSMALLOC + CRYPTO_{ZSTD,LZ4,LZO}"
scripts/config --enable ZSMALLOC \
               --enable CRYPTO_ZSTD \
               --enable CRYPTO_LZ4 \
               --enable CRYPTO_LZO

log "make ARCH=arm64 olddefconfig"
make ARCH=arm64 olddefconfig >/dev/null

# ── 5. sed override for the ZRAM choice (post-olddefconfig) ─────────────────
if ! grep -q '^CONFIG_ZRAM_DEF_COMP_ZSTD=y' .config; then
    log "ZRAM choice fell back to LZORLE — sed forcing ZSTD"
    sed -i 's/^CONFIG_ZRAM_DEF_COMP_LZORLE=y/# CONFIG_ZRAM_DEF_COMP_LZORLE is not set/' .config
    sed -i 's/^# CONFIG_ZRAM_DEF_COMP_ZSTD is not set/CONFIG_ZRAM_DEF_COMP_ZSTD=y/' .config
    grep -q 'ZRAM_DEF_COMP_ZSTD' .config || echo 'CONFIG_ZRAM_DEF_COMP_ZSTD=y' >> .config
fi

# ── 6. sanity check ─────────────────────────────────────────────────────────
log "asserting required configs landed"
grep -q '^CONFIG_LEDS_IS31FL319X=m' .config        || fail "LED module missing"
# Sans ces modules, un support externe est detecte mais reste illisible, et le
# defaut ne se voit qu'au branchement d'une cle — donc trop tard.
for fs in EXFAT_FS HFSPLUS_FS NTFS3_FS UDF_FS ISO9660_FS F2FS_FS XFS_FS; do
    grep -q "^CONFIG_${fs}=m" .config || fail "systeme de fichiers manquant : $fs"
done
grep -q '^CONFIG_SMB_SERVER=m' .config           || fail "ksmbd manquant (partage SMB)"
grep -q '^CONFIG_CIFS=m' .config                 || fail "client CIFS manquant"
grep -q '^CONFIG_ZRAM=m' .config                   || fail "ZRAM module missing"
grep -q '^CONFIG_ZRAM_DEF_COMP_ZSTD=y' .config     || fail "ZRAM zstd default missing"

# ── 7. cross-build the .deb via bindeb-pkg ──────────────────────────────────
log "bindeb-pkg starts (j$(nproc)) — this is the long step (~10-15 min on amd64)"
# DPKG_FLAGS=-d → pass -d to dpkg-buildpackage, skipping checkbuilddeps.
# Cross-build only needs libssl-dev:amd64 (host-side sign-file), pas
# libssl-dev:arm64 — que checkbuilddeps reclame pourtant, puisque le paquet
# est construit -a arm64.
#
# La variable etait KBUILD_PKG_DPKG_OPTS, que scripts/Makefile.package
# n'honore pas : le nom attendu est DPKG_FLAGS (cf. la regle bindeb-pkg).
# Le commentaire decrivait donc une intention que le code n'appliquait pas,
# et le build echouait sur « Dependances de construction non satisfaites ».
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
     -j"$(nproc)" \
     KDEB_PKGVERSION="${KDEB_PKGVERSION}" \
     DPKG_FLAGS="-d" \
     bindeb-pkg

# ── 8. collect ──────────────────────────────────────────────────────────────
log "collecting .deb artifacts to $BUILD_ROOT"
ls -la "$BUILD_ROOT"/linux-{image,headers,libc-dev}-*.deb 2>/dev/null || fail "no .deb produced"

log "DONE. Image: $(ls $BUILD_ROOT/linux-image-*_arm64.deb 2>/dev/null | head -1)"
