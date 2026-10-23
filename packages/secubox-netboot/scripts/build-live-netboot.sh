#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: build-live-netboot.sh (#3079) — SUR LE SERVEUR DE BOOT (gk2, arm64, root).
#
# Transforme une clé live MOCHAbin (secubox-mochabin-live-usb.img.gz : ESP + rootfs ext4) en live NETBOOTÉ, et publie
# des images eMMC SIGNÉES pour le flash depuis ce live :
#   TFTP  <tftp>/<nom>/  Image  board.dtb  initrd.img  boot.scr       (chargés par le U-Boot usine : dhcp/tftpboot/booti)
#   HTTP  <http>/<nom>/  filesystem.squashfs                           (récupéré par live-boot : boot=live fetch=…)
#                        <image>.img.gz  <image>.img.gz.sig  images.txt  (lus par sbx-netflash dans le live)
# Le rootfs du live reçoit : un fstab vide (celui de la clé attend sa partition USB : le live tomberait en mode
# urgence), sbx-netflash, secubox-flash-emmc et la clé PUBLIQUE de signature. La clé privée ne sort jamais du serveur.
#
#   build-live-netboot.sh --live secubox-mochabin-live-usb.img.gz [--flash img.gz]... [--nom mochabin-live]
#                         [--srv 192.168.1.200:8099] [--travail /data/sbx-netboot/travail]
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$HERE/../.." 2>/dev/null && pwd || true)"
ROOT=/srv/secubox/netboot
KEY=/etc/secubox/netboot/keys/secubox-netboot.key
PUB=/etc/secubox/netboot/keys/secubox-netboot.crt.pub
live="" nom="mochabin-live" srv="192.168.1.200:8099" travail="/data/sbx-netboot/travail" flash=()

while [ $# -gt 0 ]; do case "$1" in
    --live) live="$2"; shift 2 ;;
    --flash) flash+=("$2"); shift 2 ;;
    --nom) nom="$2"; shift 2 ;;
    --srv) srv="$2"; shift 2 ;;
    --travail) travail="$2"; shift 2 ;;
    *) echo "arg inconnu : $1" >&2; exit 2 ;;
esac; done

log() { echo "[live-netboot] $*"; }
die() { echo "[live-netboot] ERREUR : $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "à lancer en root"
[ -s "$live" ] || die "--live : image live introuvable"
case "$nom" in *[!A-Za-z0-9._-]*|"") die "--nom invalide" ;; esac
for c in losetup mksquashfs mkimage openssl rsync lsinitramfs; do command -v "$c" >/dev/null || die "outil manquant : $c"; done
[ -s "$PUB" ] || die "clé publique absente : $PUB"
[ -s "$KEY" ] || die "clé de signature absente : $KEY"
FLASHER="$HERE/../../image/sbin/secubox-flash-emmc"
[ -f "$FLASHER" ] || FLASHER="$REPO/image/sbin/secubox-flash-emmc"
[ -f "$FLASHER" ] || FLASHER="$HERE/installer/secubox-flash-emmc"
[ -f "$FLASHER" ] || die "secubox-flash-emmc introuvable (image/sbin du dépôt)"

mkdir -p "$travail"
w="$(mktemp -d "$travail/live.XXXXXX")"
loop=""
nettoie() {
    umount "$w/esp" 2>/dev/null || true; umount "$w/root" 2>/dev/null || true
    [ -n "$loop" ] && losetup -d "$loop" 2>/dev/null || true
    rm -rf "$w"
}
trap nettoie EXIT

# ── 1. la clé live, montée en lecture seule ──────────────────────────────────
log "décompression de $(basename "$live")…"
gunzip -c "$live" > "$w/live.img"
loop="$(losetup -P -r -f --show "$w/live.img")"
mkdir -p "$w/esp" "$w/root"
mount -o ro "${loop}p1" "$w/esp"
mount -o ro "${loop}p2" "$w/root"

# ── 2. noyau, DTB, initrd ────────────────────────────────────────────────────
t="$ROOT/tftp/$nom"; h="$ROOT/http/$nom"
mkdir -p "$w/out/tftp" "$w/out/http"
[ -s "$w/esp/Image" ] || die "Image absente de la partition de boot de la clé"
[ -s "$w/esp/initrd.img" ] || die "initrd.img absent de la partition de boot de la clé"
dtb="$(find "$w/esp" "$w/root/usr/lib" -name 'armada-7040-mochabin.dtb' 2>/dev/null | head -n1)"
[ -n "$dtb" ] || die "DTB armada-7040-mochabin.dtb introuvable"
cp "$w/esp/Image" "$w/out/tftp/Image"
cp "$w/esp/initrd.img" "$w/out/tftp/initrd.img"
cp "$dtb" "$w/out/tftp/board.dtb"

# L'initrd doit savoir faire un live réseau : scripts live-boot et pilote Ethernet de l'Armada 7040 (mvpp2).
lsinitramfs "$w/out/tftp/initrd.img" > "$w/initrd.lst"
grep -q 'scripts/live' "$w/initrd.lst" || die "initrd sans live-boot : boot=live fetch= impossible"
if ! grep -q 'mvpp2' "$w/initrd.lst"; then
    if grep -q 'mvpp2' "$w/root/lib/modules/"*/modules.builtin 2>/dev/null; then log "mvpp2 intégré au noyau"
    else die "initrd sans pilote mvpp2 et noyau sans mvpp2 intégré : pas de réseau au démarrage"; fi
fi

# ── 3. rootfs du live → squashfs ─────────────────────────────────────────────
log "copie du rootfs…"
rsync -aHAX --exclude=/boot/ "$w/root/" "$w/rootfs/"
mkdir -p "$w/rootfs/boot"
printf '# SecuBox live netboot (#3079) : racine en RAM (live-boot), aucune partition à monter.\n' > "$w/rootfs/etc/fstab"
install -m0755 "$HERE/installer/sbx-netflash" "$w/rootfs/usr/local/sbin/sbx-netflash"
install -m0755 "$FLASHER" "$w/rootfs/usr/local/sbin/secubox-flash-emmc"
mkdir -p "$w/rootfs/etc/secubox"
install -m0644 "$PUB" "$w/rootfs/etc/secubox/netboot-image.pub"
chroot "$w/rootfs" /bin/sh -c 'command -v openssl >/dev/null && (command -v curl >/dev/null || command -v wget >/dev/null)' \
    || die "le rootfs du live n'a pas openssl et curl/wget : sbx-netflash ne pourrait pas vérifier ni télécharger"
log "mksquashfs (xz)…"
mksquashfs "$w/rootfs" "$w/out/http/filesystem.squashfs" -comp xz -noappend -no-progress >/dev/null

# ── 4. script de démarrage U-Boot ────────────────────────────────────────────
srv_ip="${srv%%:*}"
cat > "$w/boot.cmd" <<EOF
# SecuBox MOCHAbin — live réseau (#3079). Depuis le U-Boot usine :
#   setenv serverip $srv_ip; dhcp; tftpboot \${scriptaddr} $nom/boot.scr; source \${scriptaddr}
setenv serverip $srv_ip
setenv kernel_addr_r 0x02080000
setenv fdt_addr_r 0x06f00000
setenv ramdisk_addr_r 0x07000000
tftpboot \${kernel_addr_r} $nom/Image
tftpboot \${fdt_addr_r} $nom/board.dtb
tftpboot \${ramdisk_addr_r} $nom/initrd.img
setenv bootargs console=ttyS0,115200 boot=live components fetch=http://$srv/$nom/filesystem.squashfs ip=dhcp net.ifnames=0
booti \${kernel_addr_r} \${ramdisk_addr_r}:\${filesize} \${fdt_addr_r}
EOF
cp "$w/boot.cmd" "$w/out/tftp/boot.cmd"
mkimage -A arm64 -O linux -T script -C none -n "SecuBox live netboot" -d "$w/boot.cmd" "$w/out/tftp/boot.scr" >/dev/null

# ── 5. images eMMC signées ───────────────────────────────────────────────────
: > "$w/out/http/images.txt"
for img in "${flash[@]}"; do
    [ -s "$img" ] || die "image eMMC introuvable : $img"
    b="$(basename "$img")"
    case "$b" in *.img.gz) : ;; *) die "image eMMC attendue en .img.gz : $b" ;; esac
    log "signature de $b…"
    openssl dgst -sha256 -sign "$KEY" -out "$w/out/http/$b.sig" "$img"
    openssl dgst -sha256 -verify "$PUB" -signature "$w/out/http/$b.sig" "$img" >/dev/null || die "signature non vérifiable : $b"
    ln -sf "$(readlink -f "$img")" "$w/out/http/$b"
    echo "$b $(stat -c %s "$img") $(sha256sum "$img" | awk '{print $1}')" >> "$w/out/http/images.txt"
done

# ── 6. publication (remplacement d'un bloc : le précédent est gardé en .avant) ─
for d in "$t:$w/out/tftp" "$h:$w/out/http"; do
    cible="${d%%:*}"; src="${d#*:}"
    rm -rf "$cible.avant"; [ -d "$cible" ] && mv "$cible" "$cible.avant"
    mkdir -p "$(dirname "$cible")"; cp -a "$src" "$cible"
done
chmod -R a+rX "$t" "$h"
mkdir -p /var/log/secubox/netboot
echo "$(date -Iseconds) live-netboot publie nom=$nom live=$(basename "$live") images=${#flash[@]}" >> /var/log/secubox/netboot/audit.log
log "publié : TFTP $t  HTTP $h"
ls -la "$t" "$h"
