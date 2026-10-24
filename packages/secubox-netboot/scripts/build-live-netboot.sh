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
#                         [--srv 192.168.1.200:8099] [--travail /data/sbx-netboot/travail] [--stockage DIR]
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$HERE/../.." 2>/dev/null && pwd || true)"
ROOT=/srv/secubox/netboot
KEY=/etc/secubox/netboot/keys/secubox-netboot.key
PUB=/etc/secubox/netboot/keys/secubox-netboot.crt.pub
live="" nom="mochabin-live" srv="192.168.1.200:8099" travail="/data/sbx-netboot/travail" stockage="" flash=()

while [ $# -gt 0 ]; do case "$1" in
    --live) live="$2"; shift 2 ;;
    --flash) flash+=("$2"); shift 2 ;;
    --nom) nom="$2"; shift 2 ;;
    --srv) srv="$2"; shift 2 ;;
    --travail) travail="$2"; shift 2 ;;
    --stockage) stockage="$2"; shift 2 ;;
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
# Partition de boot de la clé d'abord ; sinon le noyau Debian du rootfs (alpha.18 : la partition de boot est VIDE,
# build-mochabin-live-usb.sh cherchait boot/vmlinuz alors que Debian installe boot/vmlinuz-<version>).
noyau="" initrd=""
if [ -s "$w/esp/Image" ] && [ -s "$w/esp/initrd.img" ]; then
    noyau="$w/esp/Image"; initrd="$w/esp/initrd.img"
else
    v="$(ls -1 "$w/root/boot" | sed -n 's/^vmlinuz-//p' | sort -V | tail -n1)"
    [ -n "$v" ] || die "aucun noyau : ni Image sur la partition de boot, ni boot/vmlinuz-* dans le rootfs"
    noyau="$w/root/boot/vmlinuz-$v"; initrd="$w/root/boot/initrd.img-$v"
    [ -s "$initrd" ] || die "initrd absent : $initrd"
    log "noyau du rootfs : $v (partition de boot de la clé vide)"
fi
# booti veut une Image ARM64 non compressée : décompresser un vmlinuz gzip
if gzip -t "$noyau" 2>/dev/null; then gunzip -c "$noyau" > "$w/out/tftp/Image"; else cp "$noyau" "$w/out/tftp/Image"; fi
file -b "$w/out/tftp/Image" | grep -q 'ARM64' || die "noyau non reconnu comme Image ARM64"
cp "$initrd" "$w/out/tftp/initrd.img"
dtb="$(find "$w/esp" "$w/root/usr/lib" -name 'armada-7040-mochabin.dtb' 2>/dev/null | sort -V | tail -n1)"
[ -n "$dtb" ] || die "DTB armada-7040-mochabin.dtb introuvable"
cp "$dtb" "$w/out/tftp/board.dtb"

# L'initrd de l'image vise une racine ext4 : y ajouter squashfs et overlay, que live-boot monte.
bash "$HERE/scripts/live-initrd-modules.sh" "$w/out/tftp/initrd.img" "$w/root" || die "ajout des modules du live à l'initrd"

# L'initrd doit savoir faire un live réseau : scripts live-boot, squashfs, overlay, pilote Ethernet (mvpp2).
lsinitramfs "$w/out/tftp/initrd.img" > "$w/initrd.lst"
grep -q 'scripts/live' "$w/initrd.lst" || die "initrd sans live-boot : boot=live fetch= impossible"
grep -q '/squashfs\.ko' "$w/initrd.lst" || grep -q 'squashfs\.ko' "$w/root/lib/modules/"*/modules.builtin 2>/dev/null \
    || die "initrd sans squashfs : le live ne peut pas monter son rootfs"
grep -q '/overlay\.ko' "$w/initrd.lst" || grep -q 'overlay\.ko' "$w/root/lib/modules/"*/modules.builtin 2>/dev/null \
    || die "initrd sans overlay : le live ne peut pas monter son rootfs"
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
# SecuBox MOCHAbin — live réseau (#3079). Depuis le U-Boot usine, câble sur le WAN 1G (mvpp2-2) :
#   setenv ethact mvpp2-2; setenv ipaddr <ip libre>; setenv serverip $srv_ip
#   tftpboot \${scriptaddr} $nom/boot.scr; source \${scriptaddr}
# Le live garde le réseau de l'initrd (ip=dhcp) : mv88e6xxx bloqué (chargé tard, il fait rouvrir les ports
# mvpp2 et eth2 perd sa porteuse, #2004), systemd-networkd masqué (le netplan de l'image met eth1/eth2 dans br-lan).
# Adresses au-dessus de 0x04000000-0x04200000, réservé au firmware (PSCI/ATF) de l'Armada 7040.
setenv serverip $srv_ip
setenv kernel_addr_r 0x08000000
setenv fdt_addr_r 0x0c000000
setenv ramdisk_addr_r 0x0c100000
tftpboot \${kernel_addr_r} $nom/Image || exit
tftpboot \${fdt_addr_r} $nom/board.dtb || exit
tftpboot \${ramdisk_addr_r} $nom/initrd.img || exit
setenv bootargs console=ttyS0,115200 boot=live components fetch=http://$srv/$nom/filesystem.squashfs ip=dhcp net.ifnames=0
setenv bootargs \${bootargs} modprobe.blacklist=mv88e6xxx systemd.mask=systemd-networkd.service systemd.mask=systemd-networkd.socket
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
# Le squashfs (plus de 2 Go) ne reste pas sous /srv : sur gk2, /srv est sur la racine (eMMC à ~75 %). Il va sur le
# stockage (défaut : /data/sbx-netboot/<nom>), servi par un lien, comme les images eMMC (#3079).
[ -n "$stockage" ] || stockage="$(dirname "$travail")/$nom"
mkdir -p "$stockage"
mv -f "$h/filesystem.squashfs" "$stockage/filesystem.squashfs"
ln -sfn "$stockage/filesystem.squashfs" "$h/filesystem.squashfs"
rm -rf "$t.avant" "$h.avant"
chmod -R a+rX "$t" "$h" "$stockage"
mkdir -p /var/log/secubox/netboot
echo "$(date -Iseconds) live-netboot publie nom=$nom live=$(basename "$live") images=${#flash[@]}" >> /var/log/secubox/netboot/audit.log
log "publié : TFTP $t  HTTP $h"
ls -la "$t" "$h"
