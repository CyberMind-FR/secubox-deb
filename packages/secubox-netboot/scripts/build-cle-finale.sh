#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: build-cle-finale.sh (#3233) — SUR LE SERVEUR DE BOOT (gk2, root) : clé USB « finale » ESPRESSObin.
#
# La clé porte l'IMAGE SYSTÈME elle-même (pas un live d'outillage) :
#   - boot-usb.scr  : le système final tourne sur la clé (tests de l'image sur USB) ;
#   - autoflash.scr : même système, avec sbx_autoflash=1 → sbx-autoflash vérifie la signature de l'image rangée
#                     dans la partition SBXFLASH et l'écrit sur l'eMMC (intégration définitive), puis éteint.
# Étiquettes PROPRES À LA CLÉ (rootfs-usb, data-usb, BOOTUSB) et GUID renouvelés : l'eMMC garde rootfs/data/boot,
# jamais deux racines de même étiquette quand la clé reste branchée sur une eMMC déjà écrite.
#
#   build-cle-finale.sh --image IMG.img.xz --sortie CLE.img.gz (--sig IMG.sig | --signer-ici) [--carte espressobin-v7]
#                       [--publier NOM_DU_LIVE] [--travail DIR] [--stockage DIR]
# Jamais de signature implicite : la clé netboot fait foi pour tout le parc (lives, lots, clés USB). --sig vérifie une
# signature fournie ; --signer-ici signe avec la clé du serveur, sur décision explicite de l'exploitant. Dans les deux
# cas, l'image (nom, SHA-256, mode) est tracée dans l'audit.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$HERE/../.." 2>/dev/null && pwd || true)"
ROOT=/srv/secubox/netboot
KEY=/etc/secubox/netboot/keys/secubox-netboot.key
pub=/etc/secubox/netboot/keys/secubox-netboot.crt.pub
carte="espressobin-v7" image="" sig="" signer_ici=0 sortie="" publier="" travail="/data/sbx-netboot/travail" stockage=""

while [ $# -gt 0 ]; do case "$1" in
    --carte) carte="$2"; shift 2 ;;
    --image) image="$2"; shift 2 ;;
    --sig) sig="$2"; shift 2 ;;
    --signer-ici) signer_ici=1; shift ;;
    --sortie) sortie="$2"; shift 2 ;;
    --publier) publier="$2"; shift 2 ;;
    --travail) travail="$2"; shift 2 ;;
    --stockage) stockage="$2"; shift 2 ;;
    *) echo "arg inconnu : $1" >&2; exit 2 ;;
esac; done

log() { echo "[cle-finale] $*"; }
die() { echo "[cle-finale] ERREUR : $*" >&2; exit 1; }

# shellcheck source=live-env.sh
. "$HERE/scripts/live-env.sh"
charge_live_env "$carte" "$HERE" || die "réglages de la carte $carte refusés"
# La clé finale s'appuie sur boot-usb.cmd et le quirk eMMC de l'image ESPRESSObin : aucune autre carte.
[ "$carte" = espressobin-v7 ] || die "clé finale : seule la carte espressobin-v7 est prise en charge"
[ -n "$sig" ] || [ "$signer_ici" -eq 1 ] || die "--sig FICHIER (signature fournie) ou --signer-ici (décision explicite) requis"
[ -z "$sig" ] || [ -s "$sig" ] || die "--sig : signature introuvable"
[ -s "$image" ] || die "--image : image système introuvable"
case "$image" in *.img.xz|*.img.gz) : ;; *) die "--image : .img.xz ou .img.gz attendu" ;; esac
case "$sortie" in *.img.gz) : ;; *) die "--sortie : .img.gz attendu" ;; esac
[ -z "$publier" ] || case "$publier" in *[!A-Za-z0-9._-]*|.*) die "--publier invalide" ;; esac
[ "$(id -u)" -eq 0 ] || die "à lancer en root"
for c in sgdisk losetup e2label e2fsck tune2fs fatlabel mkfs.ext4 mkimage openssl sha256sum gzip; do
    command -v "$c" >/dev/null || die "outil manquant : $c"
done
[ -s "$pub" ] && ! grep -q 'PRIVATE KEY' "$pub" && openssl pkey -pubin -in "$pub" -noout 2>/dev/null \
    || die "clé publique absente ou invalide : $pub"
if [ "$signer_ici" -eq 1 ] || [ -n "$publier" ]; then [ -s "$KEY" ] || die "clé de signature absente : $KEY"; fi
FLASHER="$REPO/image/sbin/secubox-flash-emmc"
[ -f "$FLASHER" ] || FLASHER="$HERE/installer/secubox-flash-emmc"
[ -f "$FLASHER" ] || FLASHER="$(command -v secubox-flash-emmc || true)"
[ -n "$FLASHER" ] && [ -f "$FLASHER" ] || die "secubox-flash-emmc introuvable"

mkdir -p "$travail"
# Place : image décompressée + marge + archive de sortie (gk2 : racine et /data surveillées).
case "$image" in *.img.xz) brut="$(xz --robot -l "$image" | awk -F'\t' '$1=="totals"{print $5}')" ;;
                 *) brut=$(( $(stat -c %s "$image") * 10 )) ;; esac
besoin=$(( brut + 3 * $(stat -c %s "$image") + 512 * 1048576 ))
dispo=$(( $(df --output=avail -B1 "$travail" | tail -n1) ))
[ "$dispo" -gt "$besoin" ] || die "place insuffisante dans $travail : $((dispo/1048576)) Mo libres, $((besoin/1048576)) Mo nécessaires"
w="$(mktemp -d "$travail/cle-finale.XXXXXX")"
loop=""
nettoie() {
    for m in flash boot root; do umount "$w/mnt/$m" 2>/dev/null || true; done
    [ -n "$loop" ] && losetup -d "$loop" 2>/dev/null || true
    rm -rf --one-file-system "$w"
}
trap nettoie EXIT

# ── 1. signature de l'image, AVANT toute construction ────────────────────────
sha_image="$(sha256sum "$image" | awk '{print $1}')"
mode="fournie"
if [ "$signer_ici" -eq 1 ]; then
    sig="$w/$(basename "$image").sig"
    openssl dgst -sha256 -sign "$KEY" -out "$sig" "$image"
    mode="signee-ici"
fi
openssl dgst -sha256 -verify "$pub" -signature "$sig" "$image" >/dev/null || die "signature de l'image INVALIDE"
mkdir -p /var/log/secubox/netboot
echo "$(date -Iseconds) cle-finale image=$(basename "$image") sha256=$sha_image signature=$mode carte=$carte" \
    >> /var/log/secubox/netboot/audit.log
log "signature de $(basename "$image") vérifiée ($mode)"

# ── 2. disque de la clé : l'image + une partition SBXFLASH ───────────────────
log "décompression…"
case "$image" in *.img.xz) xz -dc "$image" > "$w/cle.img" ;; *) gzip -dc "$image" > "$w/cle.img" ;; esac
marge=$(( $(stat -c %s "$image") / 1048576 + 128 ))
truncate -s "+${marge}M" "$w/cle.img"
sgdisk -e "$w/cle.img" >/dev/null                       # GPT de secours déplacée à la nouvelle fin
sgdisk -G "$w/cle.img" >/dev/null                       # GUID du disque et des partitions renouvelés
sgdisk -n 4:0:0 -c 4:SBXFLASH -t 4:8300 "$w/cle.img" >/dev/null
loop="$(losetup -P -f --show "$w/cle.img")"
sleep 1

# ── 3. étiquettes et UUID propres à la clé ───────────────────────────────────
fatlabel "${loop}p1" BOOTUSB >/dev/null
for p in 2 3; do e2fsck -fy "${loop}p$p" >/dev/null 2>&1 || true; tune2fs -U random "${loop}p$p" >/dev/null; done
e2label "${loop}p2" rootfs-usb
e2label "${loop}p3" data-usb
mkfs.ext4 -q -L SBXFLASH "${loop}p4"

mkdir -p "$w/mnt/boot" "$w/mnt/root" "$w/mnt/flash"
# L'image est une DONNÉE : montée sans périphériques, setuid ni exécution.
mount -o nodev,nosuid,noexec "${loop}p1" "$w/mnt/boot"
mount -o nodev,nosuid,noexec "${loop}p2" "$w/mnt/root"
mount -o nodev,nosuid,noexec "${loop}p4" "$w/mnt/flash"

# Root écrit dans le rootfs monté : aucun chemin écrit ne doit sortir de l'image par un lien symbolique
# (un /etc → /etc ferait réécrire le fstab de gk2).
refuse_liens() { # RACINE
    local racine="$1" x reel
    for x in etc etc/fstab etc/secubox etc/systemd etc/systemd/system etc/systemd/system/multi-user.target.wants \
             usr usr/local usr/local/sbin; do
        [ -L "$racine/$x" ] && die "image refusée : $x est un lien symbolique"
        reel="$(realpath -m "$racine/$x")"
        case "$reel" in "$racine"|"$racine"/*) : ;; *) die "image refusée : $x sort de l'image" ;; esac
    done
}

# ── 4. racine de la clé : fstab, sbx-autoflash, flasheur, clé publique ───────
r="$w/mnt/root"
refuse_liens "$r"
[ -f "$r/etc/fstab" ] || die "image sans /etc/fstab"
sed -i -e 's/^LABEL=rootfs\([[:space:]]\)/LABEL=rootfs-usb\1/' -e 's/^LABEL=data\([[:space:]]\)/LABEL=data-usb\1/' \
    -e 's/^LABEL=boot\([[:space:]]\)/LABEL=BOOTUSB\1/' "$r/etc/fstab"
grep -q '^LABEL=rootfs-usb[[:space:]]' "$r/etc/fstab" || die "fstab de l'image inattendu : racine non désignée par LABEL=rootfs"
if grep -E -q '^LABEL=(rootfs|data|boot)[[:space:]]' "$r/etc/fstab"; then
    die "fstab : une étiquette de l'eMMC reste — la clé monterait le système de l'eMMC"
fi
for o in openssl sha256sum xz gzip dd; do
    [ -x "$r/usr/bin/$o" ] || [ -x "$r/bin/$o" ] || die "l'image n'a pas $o : sbx-autoflash ne pourrait pas vérifier ni écrire"
done
install -m0755 "$HERE/installer/sbx-autoflash" "$r/usr/local/sbin/sbx-autoflash"
install -m0755 "$FLASHER" "$r/usr/local/sbin/secubox-flash-emmc"
install -d "$r/etc/secubox"
install -m0644 "$pub" "$r/etc/secubox/netboot-image.pub"
# Empreinte GRAVÉE : l'autoflash n'écrit que l'image de cette construction (pas de retour à une image plus ancienne).
echo "$sha_image" > "$r/etc/secubox/autoflash.sha256"
sed "s/@CONSOLE@/${LIVE_CONSOLE%%,*}/g" "$HERE/installer/sbx-autoflash.service" > "$r/etc/systemd/system/sbx-autoflash.service"
chmod 0644 "$r/etc/systemd/system/sbx-autoflash.service"
mkdir -p "$r/etc/systemd/system/multi-user.target.wants"
ln -sfn /etc/systemd/system/sbx-autoflash.service "$r/etc/systemd/system/multi-user.target.wants/sbx-autoflash.service"

# ── 5. partition de boot : boot-usb.scr sur rootfs-usb, autoflash.scr ────────
b="$w/mnt/boot"
[ -f "$b/boot-usb.cmd" ] || die "image sans boot-usb.cmd : elle ne sait pas démarrer sur clé"
grep -q 'root=LABEL=rootfs ' "$b/boot-usb.cmd" || die "boot-usb.cmd inattendu : racine non désignée par LABEL=rootfs"
sed -i 's/root=LABEL=rootfs /root=LABEL=rootfs-usb /' "$b/boot-usb.cmd"
sed -e 's/^\(setenv bootargs ".*\)"$/\1 sdhci.debug_quirks2=0x40 sbx_autoflash=1"/' \
    -e '1i # SecuBox — AUTOFLASH (#3233) : même système que boot-usb.scr, sbx_autoflash=1 → l'"'"'image signée de SBXFLASH est écrite sur l'"'"'eMMC, puis la carte s'"'"'éteint.' \
    "$b/boot-usb.cmd" > "$b/autoflash.cmd"
grep -q 'sbx_autoflash=1"$' "$b/autoflash.cmd" || die "autoflash.cmd : ligne bootargs introuvable dans boot-usb.cmd"
mkimage -A arm64 -O linux -T script -C none -n "SecuBox USB" -d "$b/boot-usb.cmd" "$b/boot-usb.scr" >/dev/null
mkimage -A arm64 -O linux -T script -C none -n "SecuBox autoflash" -d "$b/autoflash.cmd" "$b/autoflash.scr" >/dev/null

# ── 6. l'image signée, pour l'autoflash ──────────────────────────────────────
cp "$image" "$w/mnt/flash/$(basename "$image")"
cp "$sig" "$w/mnt/flash/$(basename "$image").sig"
sync
for m in flash boot root; do umount "$w/mnt/$m"; done
losetup -d "$loop"; loop=""

log "compression → $sortie"
gzip -c "$w/cle.img" > "$sortie.tmp" && mv -f "$sortie.tmp" "$sortie"

# ── 7. publication à côté du live (page /netboot/) ───────────────────────────
if [ -n "$publier" ]; then
    h="$ROOT/http/$publier"
    [ -n "$stockage" ] || stockage="$(dirname "$travail")/$publier"
    mkdir -p "$h" "$stockage"
    # Publication atomique : copie, signature et vérification sur des .tmp, puis bascule des deux.
    cp -f "$sortie" "$stockage/cle-usb.img.gz.tmp"
    openssl dgst -sha256 -sign "$KEY" -out "$h/cle-usb.img.gz.sig.tmp" "$stockage/cle-usb.img.gz.tmp"
    openssl dgst -sha256 -verify "$pub" -signature "$h/cle-usb.img.gz.sig.tmp" "$stockage/cle-usb.img.gz.tmp" >/dev/null \
        || die "signature de la clé publiée invalide"
    sha_cle="$(sha256sum "$stockage/cle-usb.img.gz.tmp" | awk '{print $1}')"
    mv -f "$stockage/cle-usb.img.gz.tmp" "$stockage/cle-usb.img.gz"
    ln -sfn "$stockage/cle-usb.img.gz" "$h/cle-usb.img.gz"
    mv -f "$h/cle-usb.img.gz.sig.tmp" "$h/cle-usb.img.gz.sig"
    install -m0644 "$pub" "$h/netboot-image.pub"
    printf 'sha256\t%s\ntester\t%s\nautoflash\t%s\n' "$sha_cle" \
        "usb start; load usb 0:1 \${loadaddr} boot-usb.scr; source \${loadaddr}" \
        "usb start; load usb 0:1 \${loadaddr} autoflash.scr; source \${loadaddr}" > "$h/cle-usb.txt.tmp"
    mv -f "$h/cle-usb.txt.tmp" "$h/cle-usb.txt"
    chmod a+r "$stockage/cle-usb.img.gz" "$h/cle-usb.img.gz.sig" "$h/cle-usb.txt" "$h/netboot-image.pub"
    echo "$(date -Iseconds) cle-finale publiee carte=$carte live=$publier sha256=$sha_cle image=$(basename "$image")" \
        >> /var/log/secubox/netboot/audit.log
    log "publiée : $h/cle-usb.img.gz (sha256 $sha_cle)"
fi
log "prête : $sortie ($(du -h "$sortie" | awk '{print $1}'))"
