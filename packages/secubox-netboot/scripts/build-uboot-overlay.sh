#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: build-uboot-overlay (#737, Phase 2)
# Construit l'overlay 2ᵉ U-Boot pour une board et l'empaquette en FIT SIGNÉ
# (sbx-uboot.fit) + compile sbx-boot.scr. Deux modes :
#   --uboot-bin <u-boot.bin>   : utilise un binaire pré-construit (rapide/CI artefact)
#   --uboot-src  <dir>         : cross-compile mainline + board/<b>/uboot.fragment
# Signature : clé privée RSA-2048 en --key-dir (génère une paire si absente, dev).
#
#   build-uboot-overlay.sh --board mochabin --uboot-bin out/u-boot.bin \
#       --key-dir keys --out staging/
set -euo pipefail
readonly HERE="$(cd "$(dirname "$0")/.." && pwd)"   # packages/secubox-netboot
readonly KEYHINT="secubox-netboot"

board=""; uboot_bin=""; uboot_src=""; key_dir="$HERE/keys"; out="$HERE/staging"
while [ $# -gt 0 ]; do case "$1" in
  --board)     board="$2"; shift 2;;
  --uboot-bin) uboot_bin="$2"; shift 2;;
  --uboot-src) uboot_src="$2"; shift 2;;
  --key-dir)   key_dir="$2"; shift 2;;
  --out)       out="$2"; shift 2;;
  *) echo "arg inconnu: $1" >&2; exit 2;;
esac; done
[ -n "$board" ] || { echo "--board requis (mochabin|espressobin-v7|...)" >&2; exit 2; }

readonly bdir="$HERE/board/$board"
[ -d "$bdir" ] || { echo "board inconnue: $bdir" >&2; exit 2; }
# shellcheck disable=SC1090
. "$bdir/addrs.env"
: "${OVERLAY_LOAD:?addrs.env: OVERLAY_LOAD manquant}"
: "${DEFCONFIG:?addrs.env: DEFCONFIG manquant}"

command -v mkimage >/dev/null || { echo "mkimage (u-boot-tools) requis" >&2; exit 1; }
mkdir -p "$out" "$key_dir"

# ── clé de signature (dev: auto-générée ; prod: fournir la vôtre) ─────────────
if [ ! -f "$key_dir/$KEYHINT.key" ]; then
  echo "[build] génération clé DEV RSA-2048 ($key_dir/$KEYHINT.key) — REMPLACER en prod"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$key_dir/$KEYHINT.key"
  openssl rsa -in "$key_dir/$KEYHINT.key" -pubout -out "$key_dir/$KEYHINT.crt.pub" 2>/dev/null || true
fi
# certificat x509 attendu par mkimage pour l'embarquement de la clé publique
if [ ! -f "$key_dir/$KEYHINT.crt" ]; then
  openssl req -batch -new -x509 -key "$key_dir/$KEYHINT.key" \
    -out "$key_dir/$KEYHINT.crt" -subj "/CN=$KEYHINT/" 2>/dev/null || true
fi

# ── obtenir u-boot.bin ───────────────────────────────────────────────────────
if [ -z "$uboot_bin" ]; then
  [ -n "$uboot_src" ] || { echo "fournir --uboot-bin OU --uboot-src" >&2; exit 2; }
  echo "[build] cross-compile U-Boot ($DEFCONFIG + fragment $board)"
  : "${CROSS_COMPILE:=aarch64-linux-gnu-}"
  make -C "$uboot_src" "$DEFCONFIG"
  cat "$bdir/uboot.fragment" >> "$uboot_src/.config"
  make -C "$uboot_src" ARCH=arm CROSS_COMPILE="$CROSS_COMPILE" olddefconfig
  make -C "$uboot_src" ARCH=arm CROSS_COMPILE="$CROSS_COMPILE" -j"$(nproc)"
  uboot_bin="$uboot_src/u-boot.bin"
fi
[ -s "$uboot_bin" ] || { echo "u-boot.bin introuvable: $uboot_bin" >&2; exit 1; }

# ── FIT overlay signé ────────────────────────────────────────────────────────
its="$out/overlay-uboot.$board.its"
sed -e "s#@UBOOT_BIN@#$uboot_bin#" -e "s#@LOAD@#$OVERLAY_LOAD#" -e "s#@KEYHINT@#$KEYHINT#" \
    "$HERE/boot/overlay-uboot.its.tmpl" > "$its"
mkimage -f "$its" "$out/sbx-uboot.fit" >/dev/null
# signature (embarque la clé publique dans un dtb de contrôle optionnel -K)
mkimage -F -k "$key_dir" -r "$out/sbx-uboot.fit" >/dev/null
echo "[build] sbx-uboot.fit signé -> $out/sbx-uboot.fit"

# ── boot.scr ─────────────────────────────────────────────────────────────────
mkimage -A arm64 -O linux -T script -C none -n "secubox-netboot" \
  -d "$HERE/boot/sbx-boot.cmd" "$out/sbx-boot.scr" >/dev/null
echo "[build] sbx-boot.scr -> $out/sbx-boot.scr"

echo "[build] OK. Déposer sbx-uboot.fit + sbx-boot.scr dans le shadow buffer de la board"
echo "        (API /overlay/stage ou /boot/secubox-netboot/shadow/) puis 'overlay apply --commit'."
