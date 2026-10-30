#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: build-live-leger.sh (#3233) — live LÉGER « flasheur » pour une carte à petite RAM (ESPRESSObin, 1 Go).
#
# Debian minimale (debootstrap minbase, arm64 ; qemu-user + binfmt sur un hôte amd64) : noyau Debian, live-boot,
# réseau (systemd-networkd, DHCP), SSH par clé, sbx-netflash, secubox-flash-emmc et la clé PUBLIQUE de signature des
# images. Démarrage NORMAL (jamais rescue.target, arbitrage du 2026-10-24), sans pile SecuBox : il doit tenir en RAM
# quand il est netbooté (squashfs récupéré par live-boot).
#
# Sortie : une image au format de la clé live MOCHAbin, pour servir de DEUX façons :
#   - clé USB : p1 FAT « SBXBOOT » (Image, initrd.img, dtbs/, boot.scr pour fatload usb) + p2 ext4 « SBXLIVE » (racine) ;
#   - netboot : entrée de build-live-netboot.sh --live <sortie> --carte <carte>, qui en fait un squashfs.
#
#   build-live-leger.sh --carte espressobin-v7 --sortie secubox-espressobin-live-usb.img.gz --pub CLE.pub
#                       [--cle-ssh ID.pub] [--srv 192.168.1.200:8099] [--suite trixie] [--miroir URL] [--travail DIR]
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$HERE/../.." 2>/dev/null && pwd || true)"
carte="" sortie="" pub="" cle_ssh="" srv="192.168.1.200:8099" suite="trixie" miroir="http://deb.debian.org/debian"
travail="${TMPDIR:-/tmp}"

while [ $# -gt 0 ]; do case "$1" in
    --carte) carte="$2"; shift 2 ;;
    --sortie) sortie="$2"; shift 2 ;;
    --pub) pub="$2"; shift 2 ;;
    --cle-ssh) cle_ssh="$2"; shift 2 ;;
    --srv) srv="$2"; shift 2 ;;
    --suite) suite="$2"; shift 2 ;;
    --miroir) miroir="$2"; shift 2 ;;
    --travail) travail="$2"; shift 2 ;;
    *) echo "arg inconnu : $1" >&2; exit 2 ;;
esac; done

log() { echo "[live-leger] $*"; }
die() { echo "[live-leger] ERREUR : $*" >&2; exit 1; }

# shellcheck source=live-env.sh
. "$HERE/scripts/live-env.sh"
charge_live_env "$carte" "$HERE" || die "réglages de la carte $carte refusés"
[ -n "$sortie" ] || die "--sortie FICHIER.img.gz manquant"
case "$sortie" in *.img.gz) : ;; *) die "--sortie : .img.gz attendu" ;; esac
# Jamais une clé PRIVÉE dans l'image : elle finirait dans le squashfs servi en HTTP sur le LAN.
[ -s "$pub" ] && ! grep -q 'PRIVATE KEY' "$pub" && openssl pkey -pubin -in "$pub" -noout 2>/dev/null \
    || die "--pub : clé PUBLIQUE de signature des images attendue"
if [ -n "$cle_ssh" ]; then
    [ -s "$cle_ssh" ] && ! grep -q 'PRIVATE KEY' "$cle_ssh" && ssh-keygen -l -f "$cle_ssh" >/dev/null 2>&1 \
        || die "--cle-ssh : clé PUBLIQUE SSH attendue"
fi
KEYRING=/usr/share/keyrings/debian-archive-keyring.gpg
[ -s "$KEYRING" ] || die "trousseau Debian absent ($KEYRING) : debootstrap ne vérifierait pas les signatures"
case "$srv" in *[!A-Za-z0-9.:-]*|"") die "--srv invalide" ;; esac
[ "$(id -u)" -eq 0 ] || die "à lancer en root"
for c in debootstrap sfdisk losetup mkfs.vfat mkfs.ext4 mkimage rsync gzip openssl ssh-keygen sha256sum; do
    command -v "$c" >/dev/null || die "outil manquant : $c"
done
FLASHER="$REPO/image/sbin/secubox-flash-emmc"
[ -f "$FLASHER" ] || FLASHER="$HERE/installer/secubox-flash-emmc"
[ -f "$FLASHER" ] || FLASHER="$(command -v secubox-flash-emmc || true)"
[ -n "$FLASHER" ] && [ -f "$FLASHER" ] || die "secubox-flash-emmc introuvable"

mkdir -p "$travail"
w="$(mktemp -d "$travail/live-leger.XXXXXX")"
loop=""
nettoie() {
    for m in /dev/pts /dev /sys /proc; do umount -l "$w/root$m" 2>/dev/null || true; done
    umount "$w/mnt/boot" 2>/dev/null || true; umount "$w/mnt/root" 2>/dev/null || true
    [ -n "$loop" ] && losetup -d "$loop" 2>/dev/null || true
    rm -rf --one-file-system "$w"
}
trap nettoie EXIT

# ── 1. racine Debian minimale ────────────────────────────────────────────────
# Deux temps : socle minbase (signatures vérifiées par le trousseau Debian), puis apt-get dans la racine — les paquets
# Python (python3-argon2) cassaient la configuration de base de debootstrap lorsqu'ils étaient dans --include.
PAQUETS="systemd-sysv udev kmod linux-image-arm64 initramfs-tools zstd live-boot live-boot-initramfs-tools"
PAQUETS+=" openssh-server curl ca-certificates openssl xz-utils gzip pv util-linux e2fsprogs parted dosfstools"
# libubootenv-tool : fw_setenv, pour que sbx-uboot-env pose l'environnement U-Boot après le flash (#3271)
PAQUETS+=" iproute2 iputils-ping procps less nftables python3 python3-argon2 libubootenv-tool"
log "debootstrap $suite arm64 (minbase)…"
debootstrap --arch=arm64 --variant=minbase --keyring="$KEYRING" "$suite" "$w/root" "$miroir" > "$w/debootstrap.log" 2>&1 \
    || { tail -n 30 "$w/debootstrap.log" >&2; die "debootstrap a échoué"; }

for m in /proc /sys /dev /dev/pts; do mkdir -p "$w/root$m"; done
mount -t proc proc "$w/root/proc"; mount -t sysfs sys "$w/root/sys"
mount --bind /dev "$w/root/dev"; mount --bind /dev/pts "$w/root/dev/pts"
# Mises à jour de sécurité : le live expose sshd sur le LAN.
printf 'deb %s %s main\ndeb http://security.debian.org/debian-security %s-security main\n' "$miroir" "$suite" "$suite" \
    > "$w/root/etc/apt/sources.list"
# Aucun démon ne démarre dans la racine en construction.
printf '#!/bin/sh\nexit 101\n' > "$w/root/usr/sbin/policy-rc.d"; chmod 0755 "$w/root/usr/sbin/policy-rc.d"
log "paquets du live…"
# shellcheck disable=SC2086
chroot "$w/root" /bin/sh -c "apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends $PAQUETS" \
    > "$w/apt.log" 2>&1 || { tail -n 30 "$w/apt.log" >&2; die "installation des paquets du live"; }
rm -f "$w/root/usr/sbin/policy-rc.d"

# ── 2. configuration ─────────────────────────────────────────────────────────
echo "sbx-live" > "$w/root/etc/hostname"
# Identifiant de machine vidé : régénéré au démarrage (sinon tous les lives présentent le même client DHCP).
: > "$w/root/etc/machine-id"; rm -f "$w/root/var/lib/dbus/machine-id"
printf '127.0.0.1\tlocalhost\n127.0.1.1\tsbx-live\n' > "$w/root/etc/hosts"
printf 'LABEL=SBXLIVE / ext4 defaults,noatime 0 1\n' > "$w/root/etc/fstab"
mkdir -p "$w/root/etc/systemd/network"
printf '[Match]\nName=eth0 end0\n\n[Network]\nDHCP=yes\n' > "$w/root/etc/systemd/network/20-eth.network"
chroot "$w/root" systemctl enable systemd-networkd.service >/dev/null 2>&1

# Console série : accès de banc (physique), session root sans mot de passe ; aucun mot de passe nulle part.
consol="${LIVE_CONSOLE%%,*}"
mkdir -p "$w/root/etc/systemd/system/serial-getty@$consol.service.d"
cat > "$w/root/etc/systemd/system/serial-getty@$consol.service.d/autologin.conf" <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --keep-baud 115200,57600,38400,9600 %I \$TERM
EOF
chroot "$w/root" passwd -l root >/dev/null

# SSH : par clé seulement (celle passée en --cle-ssh), jamais par mot de passe.
mkdir -p "$w/root/etc/ssh/sshd_config.d"
printf 'PermitRootLogin prohibit-password\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' \
    > "$w/root/etc/ssh/sshd_config.d/10-secubox-live.conf"
if [ -n "$cle_ssh" ]; then
    install -d -m0700 "$w/root/root/.ssh"
    install -m0600 "$cle_ssh" "$w/root/root/.ssh/authorized_keys"
fi
rm -f "$w/root"/etc/ssh/ssh_host_*      # clés d'hôte régénérées au démarrage : jamais les mêmes sur deux lives
# ssh.service de Debian lance `sshd -t` en ExecStartPre : sans clés il échoue AVANT tout ExecStartPre ajouté. On
# remplace la liste : génération des clés d'abord, contrôle de la configuration ensuite.
mkdir -p "$w/root/etc/systemd/system/ssh.service.d"
printf '[Service]\nExecStartPre=\nExecStartPre=/usr/bin/ssh-keygen -A\nExecStartPre=/usr/sbin/sshd -t\n' \
    > "$w/root/etc/systemd/system/ssh.service.d/10-cles-hote.conf"

# Pare-feu : refus par défaut en entrée ; SSH, DHCP client et ICMP seulement.
cat > "$w/root/etc/nftables.conf" <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
table inet sbx_live {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif "lo" accept
        meta l4proto { icmp, ipv6-icmp } accept
        udp sport 67 udp dport 68 accept
        udp sport 547 udp dport 546 accept
        tcp dport 22 accept
    }
    chain forward { type filter hook forward priority 0; policy drop; }
}
EOF
chroot "$w/root" systemctl enable nftables.service >/dev/null 2>&1

# Outils de flash et clé PUBLIQUE de signature des images (la clé privée ne quitte jamais le serveur).
install -m0755 "$HERE/installer/sbx-netflash" "$w/root/usr/local/sbin/sbx-netflash"
install -m0755 "$HERE/installer/sbx-netflash-profil" "$w/root/usr/local/sbin/sbx-netflash-profil"
install -m0755 "$FLASHER" "$w/root/usr/local/sbin/secubox-flash-emmc"
install -d "$w/root/etc/secubox"
install -m0644 "$pub" "$w/root/etc/secubox/netboot-image.pub"
# Après le flash (#3271) : sbx-uboot-env propose (ou écrit, sur --ecrire-spi) l'environnement U-Boot de la carte.
install -m0755 "$HERE/installer/sbx-uboot-env" "$w/root/usr/local/sbin/sbx-uboot-env"
python3 "$HERE/scripts/uboot-env.py" live-conf "$carte" > "$w/root/etc/secubox/uboot-env.json" \
    || die "préparation U-Boot de $carte non générée (board/$carte/uboot-env.env)"
cat > "$w/root/etc/motd" <<EOF

  SecuBox — live léger $LIVE_TITRE (#3233)
    sbx-netflash --list                    images servies par http://$srv/$LIVE_NOM
    sbx-netflash --image NOM               vérifie la signature et écrit l'eMMC (demande « FLASH »)
    sbx-netflash --image NOM --nom BOX     en plus : jonction automatique au maillage (lot signé du maître)

EOF

# Initrd : tous les pilotes (racine sur clé USB, réseau mvneta, squashfs et overlay pour le netboot).
sed -i 's/^MODULES=.*/MODULES=most/' "$w/root/etc/initramfs-tools/initramfs.conf"
chroot "$w/root" update-initramfs -u -k all > "$w/initramfs.log" 2>&1 || { tail -n 20 "$w/initramfs.log" >&2; die "update-initramfs"; }

# Allègement : listes apt, documentation, pages de manuel, locales.
chroot "$w/root" apt-get clean
rm -rf "$w/root"/var/lib/apt/lists/* "$w/root"/usr/share/man/* "$w/root"/usr/share/info/*
find "$w/root/usr/share/doc" -type f ! -name copyright -delete 2>/dev/null || true    # licences gardées
find "$w/root/usr/share/locale" -mindepth 1 -maxdepth 1 ! -name 'fr*' ! -name 'en*' -exec rm -rf {} + 2>/dev/null || true
for m in /dev/pts /dev /sys /proc; do umount -l "$w/root$m"; done

# ── 3. partition de boot : noyau, initrd, DTB, boot.scr (U-Boot usine, clé USB) ──
v="$(ls -1 "$w/root/boot" | sed -n 's/^vmlinuz-//p' | sort -V | tail -n1)"
[ -n "$v" ] || die "aucun noyau dans la racine"
mkdir -p "$w/boot/dtbs"
if gzip -t "$w/root/boot/vmlinuz-$v" 2>/dev/null; then gunzip -c "$w/root/boot/vmlinuz-$v" > "$w/boot/Image"
else cp "$w/root/boot/vmlinuz-$v" "$w/boot/Image"; fi
cp "$w/root/boot/initrd.img-$v" "$w/boot/initrd.img"
dtb="$(find "$w/root/usr/lib" -name "$LIVE_DTB" 2>/dev/null | sort -V | tail -n1)"
[ -n "$dtb" ] || die "DTB $LIVE_DTB introuvable dans le noyau $v"
cp "$dtb" "$w/boot/dtbs/$LIVE_DTB"
cat > "$w/boot/boot.cmd" <<EOF
# SecuBox $LIVE_TITRE — live léger sur clé USB (#3233). Depuis le U-Boot usine (console série) :
#   usb start; fatload usb 0:1 $LIVE_SCRIPT_ADDR boot.scr; source $LIVE_SCRIPT_ADDR
setenv kernel_addr_r $LIVE_KERNEL_ADDR
setenv fdt_addr_r $LIVE_FDT_ADDR
setenv ramdisk_addr_r $LIVE_RAMDISK_ADDR
fatload usb 0:1 \${kernel_addr_r} Image || exit
fatload usb 0:1 \${fdt_addr_r} dtbs/$LIVE_DTB || exit
fatload usb 0:1 \${ramdisk_addr_r} initrd.img || exit
setenv bootargs console=$LIVE_CONSOLE root=LABEL=SBXLIVE rootwait rw net.ifnames=0 sbx_srv=$srv sbx_dir=$LIVE_NOM
setenv bootargs \${bootargs} $LIVE_BOOTARGS
booti \${kernel_addr_r} \${ramdisk_addr_r}:\${filesize} \${fdt_addr_r}
EOF
mkimage -A arm64 -O linux -T script -C none -n "SecuBox live leger USB" -d "$w/boot/boot.cmd" "$w/boot/boot.scr" >/dev/null
# Préparation de l'environnement U-Boot sur la clé (#3271) : usb start; load usb 0:1 ${loadaddr} fix-bootcmd.scr; …
prep="$(fix_bootcmd_de "$carte" "$HERE")" || die "script de préparation U-Boot de $carte refusé"
cp "$prep" "$w/boot/fix-bootcmd.scr"

# ── 4. image : p1 FAT 256 Mo + p2 ext4 à la taille de la racine (+ 30 %) ─────
racine_mo=$(( $(du -sm "$w/root" | awk '{print $1}') * 13 / 10 + 64 ))
total_mo=$(( 1 + 256 + racine_mo ))
log "racine $(du -sh "$w/root" | awk '{print $1}'), image ${total_mo} Mo"
truncate -s "${total_mo}M" "$w/live.img"
printf 'label: dos\nstart=1MiB, size=256MiB, type=c, bootable\nstart=257MiB, type=83\n' | sfdisk -q "$w/live.img"
loop="$(losetup -P -f --show "$w/live.img")"
mkfs.vfat -F 32 -n SBXBOOT "${loop}p1" >/dev/null
mkfs.ext4 -q -L SBXLIVE "${loop}p2"
mkdir -p "$w/mnt/boot" "$w/mnt/root"
mount "${loop}p1" "$w/mnt/boot"; mount "${loop}p2" "$w/mnt/root"
cp -r "$w/boot/." "$w/mnt/boot/"
rsync -aHAX "$w/root/" "$w/mnt/root/"
sync; umount "$w/mnt/boot"; umount "$w/mnt/root"
losetup -d "$loop"; loop=""
log "compression → $sortie"
gzip -c "$w/live.img" > "$sortie.tmp" && mv -f "$sortie.tmp" "$sortie"
log "prêt : $sortie ($(du -h "$sortie" | awk '{print $1}')), noyau $v, DTB $LIVE_DTB"
mkdir -p /var/log/secubox/netboot
echo "$(date -Iseconds) live-leger construit carte=$carte sortie=$(basename "$sortie") sha256=$(sha256sum "$sortie" | awk '{print $1}') cle_images=$(openssl pkey -pubin -in "$pub" -outform DER 2>/dev/null | sha256sum | cut -c1-16) cle_ssh=$( [ -n "$cle_ssh" ] && ssh-keygen -l -f "$cle_ssh" | awk '{print $2}' || echo aucune)" \
    >> /var/log/secubox/netboot/audit.log
