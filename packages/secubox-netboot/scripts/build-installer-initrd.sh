#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: build-installer-initrd (#737, niveau B3)
# Assemble l'initramfs INSTALLEUR arm64 : busybox + openssl + la CLÉ PUBLIQUE de
# signature d'image + installer/init → initrd.img (cpio.gz). DOIT tourner sur arm64
# (board) ou avec des binaires arm64 fournis : les binaires embarqués DOIVENT être
# arm64, sinon l'initramfs ne s'exécute pas sur le DUT.
#
#   build-installer-initrd.sh --pubkey /etc/secubox/netboot/keys/secubox-netboot.crt.pub \
#       --out /var/lib/secubox/netboot/staging/<image>/initrd.img
set -euo pipefail
readonly HERE="$(cd "$(dirname "$0")/.." && pwd 2>/dev/null || echo /usr/share/secubox/netboot)"
pubkey=""; out="$HERE/staging/initrd.img"; busybox=""; arch="$(uname -m)"
while [ $# -gt 0 ]; do case "$1" in
  --pubkey)  pubkey="$2"; shift 2;;
  --out)     out="$2"; shift 2;;
  --busybox) busybox="$2"; shift 2;;   # busybox arm64 (static de préférence)
  *) echo "arg inconnu: $1" >&2; exit 2;;
esac; done
[ -n "$pubkey" ] || { echo "--pubkey requis (clé publique de signature d'image)" >&2; exit 2; }
[ -s "$pubkey" ] || { echo "clé publique absente: $pubkey" >&2; exit 1; }

case "$arch" in aarch64|arm64) : ;; *)
  echo "WARN: hôte $arch != arm64 — fournir des binaires arm64 (--busybox arm64) ; sinon l'initrd ne bootera pas sur le DUT" >&2 ;;
esac

root="$(mktemp -d)"; trap 'rm -rf "$root"' EXIT
mkdir -p "$root"/{bin,sbin,etc/secubox,proc,sys,dev,tmp,usr/bin,usr/sbin,lib}

# ── busybox (fournit sh, wget, udhcpc, ip, dd, mount, reboot…) ────────────────
if [ -z "$busybox" ]; then busybox="$(command -v busybox || true)"; fi
[ -n "$busybox" ] && [ -x "$busybox" ] || { echo "busybox introuvable (apt install busybox-static ; ou --busybox)" >&2; exit 1; }
install -m0755 "$busybox" "$root/bin/busybox"
for ap in sh wget udhcpc ip dd mount umount reboot sync sleep cat grep awk tr ls mkdir ln chmod; do
  ln -sf busybox "$root/bin/$ap"
done

# ── openssl (vérification de signature) + ses libs ───────────────────────────
ossl="$(command -v openssl || true)"
[ -n "$ossl" ] || { echo "openssl requis" >&2; exit 1; }
install -m0755 "$ossl" "$root/usr/bin/openssl"
# copier les libs partagées (si openssl n'est pas statique)
if command -v ldd >/dev/null 2>&1; then
  ldd "$ossl" 2>/dev/null | awk '/=>/{print $3} /^\t\//{print $1}' | while read -r lib; do
    [ -f "$lib" ] || continue
    d="$root$(dirname "$lib")"; mkdir -p "$d"; cp -aL "$lib" "$d/" 2>/dev/null || true
  done
  # le loader dynamique
  for ld in /lib/ld-linux-aarch64.so.1 /lib64/ld-linux-aarch64.so.1; do
    [ -f "$ld" ] && { mkdir -p "$root$(dirname "$ld")"; cp -aL "$ld" "$root$ld"; }
  done
fi

# ── fw_setenv (optionnel : repasser en boot local) ───────────────────────────
fwse="$(command -v fw_setenv || true)"
[ -n "$fwse" ] && install -m0755 "$fwse" "$root/usr/sbin/fw_setenv" 2>/dev/null || true
fwpe="$(command -v fw_printenv || true)"
[ -n "$fwpe" ] && install -m0755 "$fwpe" "$root/usr/sbin/fw_printenv" 2>/dev/null || true

# ── clé publique + init ──────────────────────────────────────────────────────
# accepte une clé PEM publique ; si un cert x509 est fourni, en extraire la pubkey
if openssl pkey -pubin -in "$pubkey" -noout >/dev/null 2>&1; then
  install -m0644 "$pubkey" "$root/etc/secubox/netboot-image.pub"
elif openssl x509 -in "$pubkey" -pubkey -noout > "$root/etc/secubox/netboot-image.pub" 2>/dev/null; then
  :
else
  cp -f "$pubkey" "$root/etc/secubox/netboot-image.pub"
fi
install -m0755 "$HERE/installer/init" "$root/init"

# ── cpio + gzip ──────────────────────────────────────────────────────────────
mkdir -p "$(dirname "$out")"
( cd "$root" && find . | cpio -o -H newc 2>/dev/null ) | gzip -9 > "$out"
echo "[installer] initrd -> $out ($(du -h "$out" | cut -f1))"
echo "[installer] binaires arch: $(file -b "$root/bin/busybox" 2>/dev/null | cut -d, -f2 | xargs || echo '?') — DOIT être ARM aarch64 pour le DUT"
