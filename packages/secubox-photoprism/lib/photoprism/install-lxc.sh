#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: secubox-photoprism :: install-lxc.sh
# CyberMind — https://cybermind.fr
#
# Idempotent native-LXC bootstrap for the PhotoPrism module. Safe to re-run.
# Follows docs/MODULE-GUIDELINES.md §3 (mirror of grafana / secubox-peertube).
#
# PhotoPrism runs NATIVELY inside a dedicated Debian LXC — the official Linux
# build (dl.photoprism.app, amd64/arm64, glibc >= 2.35), a systemd unit, a
# dedicated `photoprism` user. LXC ONLY: no podman, no docker, ever
# (.claude/PATTERNS.md Pattern 11, #1742, #1743). Photos live on the host at /data/shared/photos,
# which Nextcloud also mounts (see secubox-nextcloud "PhotoLibrary" external
# storage) — phone → Nextcloud → /data/shared/photos → PhotoPrism originals.

set -euo pipefail

readonly LXC_NAME="${SECUBOX_LXC_NAME:-photoprism}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.130}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
readonly LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
readonly LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
readonly DEBIAN_SUITE="${SECUBOX_DEBIAN_SUITE:-bookworm}"
readonly DATA_DIR="${SECUBOX_DATA_DIR:-/data/photoprism}"
readonly SHARED_PHOTOS="${SECUBOX_SHARED_PHOTOS:-/data/shared/photos}"
readonly STATE_DIR="${SECUBOX_STATE_DIR:-/var/lib/secubox/photoprism}"
readonly SECRETS_DIR="${SECUBOX_SECRETS_DIR:-/etc/secubox/secrets}"
readonly SENTINEL="$STATE_DIR/.lxc-provisioned"
# Nom dérivé du domaine de CETTE box, jamais celui de gk2 (#1723).
readonly PUBLIC_HOSTNAME="${SECUBOX_PHOTOPRISM_HOSTNAME:-$(secubox-domaine photoprism 2>/dev/null || true)}"
# Construction officielle native ; SECUBOX_PHOTOPRISM_MAJ=1 la retélécharge.
readonly PAQUET_URL="${SECUBOX_PHOTOPRISM_URL:-https://dl.photoprism.app/pkg/linux/$(dpkg --print-architecture).tar.gz}"
readonly MAJ="${SECUBOX_PHOTOPRISM_MAJ:-0}"
readonly HTTP_PORT="${SECUBOX_PHOTOPRISM_PORT:-2342}"
# PhotoPrism's built-in auto-index only fires for its own UI uploads; the
# index timer below catches Nextcloud-synced files. AUTO_INDEX is the delay
# (s) before re-indexing after a UI change; -1 disables.
readonly AUTO_INDEX="${SECUBOX_PHOTOPRISM_AUTO_INDEX:-300}"
# Vide = PhotoPrism choisit selon les cœurs ; 1 sur une petite box arm64.
readonly WORKERS="${SECUBOX_PHOTOPRISM_WORKERS:-}"
readonly LXC_ROOT_UID="${SECUBOX_LXC_ROOT_UID:-100000}"

log()  { printf '[photoprism-install] %s\n' "$*"; }
fail() { printf '[photoprism-install] ERROR: %s\n' "$*" >&2; exit 1; }
[ -n "$PUBLIC_HOSTNAME" ] || fail "domaine de la box inconnu ([global] domain) — SECUBOX_PHOTOPRISM_HOSTNAME ou secubox-domaine"
la() { lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- "$@"; }

# ── Preflight ────────────────────────────────────────────────────────────────
require_cmds() {
    for c in lxc-create lxc-info lxc-start lxc-attach openssl; do
        command -v "$c" >/dev/null 2>&1 || fail "$c not installed"
    done
}

ensure_dirs() {
    install -d -m 0755 -o root -g root "$LXC_PATH"
    install -d -m 0755 "$STATE_DIR" 2>/dev/null || true
    # État canonique du dossier des secrets (#1689, #1701) : root:secubox 0750,
    # comme le tmpfiles de secubox-core. `0700 root:root` le rendait à root
    # seul ET mettait le masque ACL à « --- » : chaque provision coupait tous
    # les services qui lisent un secret (auth, radio, socialrelay, bbs…).
    install -d -m 0750 -o root -g secubox "$SECRETS_DIR"
    install -d -m 0750 "$DATA_DIR/storage" "$DATA_DIR/import"
    # Shared photo library — Nextcloud (www-data) writes, PhotoPrism reads.
    # 0777 so both LXCs' service UIDs can use it (both map root→100000, but
    # NC writes as www-data 100033). Acceptable on a single-appliance box.
    install -d -m 0777 "$SHARED_PHOTOS"
    # Premier niveau seulement, et seulement s'il est encore à root : le
    # conteneur rend storage/ et import/ à l'utilisateur photoprism ; un
    # `chown -R` de l'hôte à chaque passage le lui reprenait (cf. peertube #1729).
    for d in "$DATA_DIR" "$DATA_DIR/storage" "$DATA_DIR/import" "$SHARED_PHOTOS"; do
        [ "$(stat -c %u "$d")" -lt "$LXC_ROOT_UID" ] && chown "$LXC_ROOT_UID:$LXC_ROOT_UID" "$d"
    done
    return 0
}

ensure_bridge() {
    if ! ip link show "$LXC_BRIDGE" >/dev/null 2>&1; then
        log "Creating bridge $LXC_BRIDGE @ ${LXC_GW}/24 ..."
        ip link add name "$LXC_BRIDGE" type bridge
        ip addr add "${LXC_GW}/24" dev "$LXC_BRIDGE"
        ip link set "$LXC_BRIDGE" up
        cat > /etc/systemd/network/10-secubox-lxc-bridge.netdev <<EOF
[NetDev]
Name=$LXC_BRIDGE
Kind=bridge
EOF
        cat > /etc/systemd/network/10-secubox-lxc-bridge.network <<EOF
[Match]
Name=$LXC_BRIDGE

[Network]
Address=${LXC_GW}/24
ConfigureWithoutCarrier=yes
IPMasquerade=ipv4
EOF
        systemctl reload systemd-networkd 2>/dev/null || true
    fi
}

ensure_masquerade() {
    if ! nft list table ip lxc 2>/dev/null | grep -q 'saddr 10.100.0.0/24'; then
        log "Adding nftables MASQUERADE for 10.100.0.0/24 ..."
        nft 'add table ip lxc' 2>/dev/null || true
        nft 'add chain ip lxc postrouting { type nat hook postrouting priority srcnat ; policy accept ; }' 2>/dev/null || true
        nft 'add rule ip lxc postrouting ip saddr 10.100.0.0/24 ip daddr != 10.100.0.0/24 counter masquerade' 2>/dev/null || true
    fi
}

# ── LXC lifecycle ────────────────────────────────────────────────────────────
lxc_state() {
    lxc-info -n "$LXC_NAME" -P "$LXC_PATH" 2>/dev/null \
        | awk -F: '/^State:/ { gsub(/ /,"",$2); print tolower($2) }'
}

create_lxc() {
    if [ -d "$LXC_PATH/$LXC_NAME/rootfs" ]; then
        log "LXC '$LXC_NAME' already exists — skipping debootstrap"
        return
    fi
    log "Creating LXC '$LXC_NAME' (debian $DEBIAN_SUITE) ..."
    lxc-create -n "$LXC_NAME" -t download -P "$LXC_PATH" -- \
        --dist debian --release "$DEBIAN_SUITE" --arch "$(dpkg --print-architecture)"
}

write_lxc_config() {
    local cfg="$LXC_PATH/$LXC_NAME/config" repris=""
    # Le paquet ne possède que l'identité du conteneur (idmap, rootfs, réseau)
    # et ses trois montages. Le reste d'une config existante appartient à
    # d'autres : lxc.start.* et lxc.cgroup2.* sont posés par le cycle de vie
    # on-demand, secubox-tuning-apply et lxcstagger ; des montages ajoutés hors
    # paquet (gk2 : dossiers Photos de comptes Nextcloud sous originals/<compte>)
    # disparaîtraient, et PhotoPrism marquerait leurs photos manquantes.
    [ -f "$cfg" ] && repris="$(grep -E '^lxc\.(start\.|cgroup2\.|mount\.entry)' "$cfg" \
        | grep -vE ' var/lib/photoprism/(originals|storage|import) ' || true)"
    log "Pinning LXC network: $LXC_IP/24 on $LXC_BRIDGE; bind mounts"
    cat > "$cfg" <<EOF
# SecuBox-managed — see secubox-photoprism / install-lxc.sh
lxc.include = /usr/share/lxc/config/debian.common.conf
lxc.arch = linux64

lxc.idmap = u 0 $LXC_ROOT_UID 65536
lxc.idmap = g 0 $LXC_ROOT_UID 65536

lxc.rootfs.path = dir:$LXC_PATH/$LXC_NAME/rootfs
lxc.uts.name = $LXC_NAME

lxc.net.0.type = veth
lxc.net.0.link = $LXC_BRIDGE
lxc.net.0.flags = up
lxc.net.0.ipv4.address = $LXC_IP/24
lxc.net.0.ipv4.gateway = $LXC_GW
lxc.net.0.name = eth0

# Shared photo library (Nextcloud writes here) + PhotoPrism-private dirs.
lxc.mount.entry = $SHARED_PHOTOS var/lib/photoprism/originals none bind,create=dir 0 0
lxc.mount.entry = $DATA_DIR/storage var/lib/photoprism/storage none bind,create=dir 0 0
lxc.mount.entry = $DATA_DIR/import var/lib/photoprism/import none bind,create=dir 0 0
EOF
    if [ -n "$repris" ]; then
        log "Réglages existants conservés : $(printf '%s\n' "$repris" | wc -l) ligne(s)"
        printf '\n# Conservé de la config existante (cycle de vie, réglages, montages locaux)\n%s\n' \
            "$repris" >> "$cfg"
    else
        cat >> "$cfg" <<'EOF'

lxc.cgroup2.memory.high = 1500M
lxc.cgroup2.memory.max = 2G

lxc.start.auto = 1
lxc.start.delay = 5
EOF
    fi

    # DECALER LA PROPRIETE DU ROOTFS SUR L'IDMAP.
    #
    # La config ci-dessus declare `lxc.idmap = u 0 100000 65536` : dans le
    # conteneur, l'uid 0 EST l'uid 100000 de l'hote. Or `lxc-create -t
    # download` deballe le rootfs en root, donc en uid 0 de l'HOTE. L'init du
    # conteneur ne peut alors pas lire sa propre racine, et lxc-start echoue :
    #
    #   conf - lxc_setup_rootfs_prepare_root - Failed to setup rootfs
    #
    # Le message ne nomme ni les droits ni l'idmap, ce qui envoie chercher du
    # cote du reseau, d'AppArmor ou des espaces de noms — trois fausses pistes
    # verifiees une a une sur la VM trixie avant d'arriver ici (#1308).
    #
    # Idempotent : rejouer ne coute qu'un parcours. On ne decale QUE si la
    # racine est encore a l'uid 0, pour ne pas re-decaler un rootfs deja bon.
    if [ -d "$LXC_PATH/$LXC_NAME/rootfs" ] \
       && [ "$(stat -c %u "$LXC_PATH/$LXC_NAME/rootfs")" = "0" ]; then
        log "Decalage de la propriete du rootfs sur l'idmap (0 -> 100000)..."
        chown -R 100000:100000 "$LXC_PATH/$LXC_NAME/rootfs"
        chown 100000:100000 "$LXC_PATH/$LXC_NAME"
    fi
}

ensure_resolv() {
    log "Seeding /etc/resolv.conf in LXC ..."
    la sh -c 'rm -f /etc/resolv.conf; printf "nameserver 1.1.1.1\nnameserver 9.9.9.9\n" > /etc/resolv.conf'
}

start_lxc() {
    [ "$(lxc_state)" = "running" ] && { log "LXC already running"; return; }
    log "Starting LXC '$LXC_NAME' ..."
    lxc-start -n "$LXC_NAME" -P "$LXC_PATH"
}

wait_for_network() {
    log "Waiting for LXC network ..."
    for _ in $(seq 1 30); do
        la ping -c1 -W1 "$LXC_GW" >/dev/null 2>&1 && return 0
        sleep 1
    done
    fail "LXC did not reach $LXC_GW within 30s"
}

# ── PhotoPrism NATIF dans le LXC (jamais podman ni docker — #1743) ─────────
install_photoprism_in_lxc() {
    local admin_pw
    admin_pw="$(cat "$SECRETS_DIR/photoprism-admin" 2>/dev/null || true)"
    if [ -z "$admin_pw" ]; then
        admin_pw="$(openssl rand -hex 16)"
        ( umask 077; echo "$admin_pw" > "$SECRETS_DIR/photoprism-admin" )
        chmod 600 "$SECRETS_DIR/photoprism-admin"
    fi

    log "Installing PhotoPrism (native build) in '$LXC_NAME' ..."
    # Le mot de passe passe par stdin, jamais par argv ni par la sortie.
    printf '%s\n' "$admin_pw" | la env \
        SITE_URL="https://$PUBLIC_HOSTNAME/" PAQUET_URL="$PAQUET_URL" MAJ="$MAJ" \
        HTTP_PORT="$HTTP_PORT" AUTO_INDEX="$AUTO_INDEX" PROXY="$LXC_GW" WORKERS="$WORKERS" \
        DEBIAN_FRONTEND=noninteractive LC_ALL=C LANG=C \
        bash -e -c "$(cat <<'INNER'
set -euo pipefail
read -r ADMIN_PW

echo '[1/5] dépendances natives (libvips42 : seule bibliothèque absente du binaire)'
apt-get update -q
apt-get install -y -q --no-install-recommends ca-certificates curl libvips42 ffmpeg \
    libimage-exiftool-perl libheif-examples
# LXC UNIQUEMENT : l'ancienne installation mettait podman DANS ce conteneur.
if dpkg -l podman 2>/dev/null | grep -q '^ii'; then
    echo '  purge de podman (reliquat de l ancienne installation)'
    systemctl disable --now photoprism.service 2>/dev/null || true
    podman rm -f photoprism >/dev/null 2>&1 || true
    apt-get purge -y -q podman buildah crun conmon slirp4netns fuse-overlayfs 2>/dev/null || true
    apt-get autoremove -y -q >/dev/null 2>&1 || true
fi
if [ -d /var/lib/containers ]; then
    # L'overlay de podman reste monté après la purge : démonter d'abord,
    # du plus profond au plus haut, sinon « Device or resource busy ».
    awk '$5 ~ "^/var/lib/containers" { print $5 }' /proc/self/mountinfo \
        | sort -r | while read -r m; do umount -l "$m" 2>/dev/null || true; done
    rm -rf /var/lib/containers 2>/dev/null \
        || echo '  avertissement : /var/lib/containers non effacé (reliquat inerte)'
fi

echo '[2/5] construction officielle'
if [ ! -x /opt/photoprism/bin/photoprism ] || [ "$MAJ" = 1 ]; then
    rm -rf /opt/photoprism.nouveau && mkdir -p /opt/photoprism.nouveau
    curl -fsSL "$PAQUET_URL" | tar -xz -C /opt/photoprism.nouveau
    /opt/photoprism.nouveau/bin/photoprism --version >/dev/null
    rm -rf /opt/photoprism.ancien
    [ -d /opt/photoprism ] && mv /opt/photoprism /opt/photoprism.ancien
    mv /opt/photoprism.nouveau /opt/photoprism
    rm -rf /opt/photoprism.ancien
fi
/opt/photoprism/bin/photoprism --version

echo '[3/5] utilisateur, répertoires, configuration'
id photoprism >/dev/null 2>&1 || adduser --system --group --home /var/lib/photoprism \
    --no-create-home --shell /usr/sbin/nologin photoprism
install -d -o photoprism -g photoprism /var/lib/photoprism
# Montages liés : storage/ et import/ à photoprism (l'ancien conteneur les
# laissait à root) ; originals/ est partagé avec Nextcloud (0777), on n'y touche pas.
for d in storage import; do
    [ "$(stat -c %U /var/lib/photoprism/$d)" = photoprism ] || chown -R photoprism:photoprism /var/lib/photoprism/$d
done
install -d -m 0750 -o root -g photoprism /etc/photoprism
umask 077
cat > /etc/photoprism/photoprism.env <<ENV
PHOTOPRISM_ADMIN_USER=admin
PHOTOPRISM_ADMIN_PASSWORD=$ADMIN_PW
PHOTOPRISM_ASSETS_PATH=/opt/photoprism/assets
PHOTOPRISM_STORAGE_PATH=/var/lib/photoprism/storage
PHOTOPRISM_CONFIG_PATH=/var/lib/photoprism/storage/config
PHOTOPRISM_ORIGINALS_PATH=/var/lib/photoprism/originals
PHOTOPRISM_IMPORT_PATH=/var/lib/photoprism/import
PHOTOPRISM_DATABASE_DRIVER=sqlite
PHOTOPRISM_HTTP_HOST=0.0.0.0
PHOTOPRISM_HTTP_PORT=$HTTP_PORT
PHOTOPRISM_AUTO_INDEX=$AUTO_INDEX
PHOTOPRISM_SITE_URL=$SITE_URL
# TLS terminé par HAProxy : le site est en https:// mais nginx parle en clair
# au conteneur ; sans ceci PhotoPrism tenterait son propre TLS.
PHOTOPRISM_DISABLE_TLS=true
# nginx de l'hôte joint le conteneur depuis la passerelle du pont.
PHOTOPRISM_TRUSTED_PROXY=$PROXY
ENV
[ -z "$WORKERS" ] || echo "PHOTOPRISM_WORKERS=$WORKERS" >> /etc/photoprism/photoprism.env
chown root:photoprism /etc/photoprism/photoprism.env
chmod 0640 /etc/photoprism/photoprism.env
umask 022

echo '[4/5] lanceur photoprism-cli (ctl et API passent par lui)'
cat > /usr/local/bin/photoprism-cli <<'CLI'
#!/bin/sh
# PhotoPrism en ligne de commande : même environnement, même compte que le service.
set -a; . /etc/photoprism/photoprism.env; set +a
# Répertoire lisible par photoprism : lancé depuis /root, le binaire panique
# dès son init (« stat .: permission denied »).
cd /var/lib/photoprism || exit 1
exec runuser -u photoprism -- /opt/photoprism/bin/photoprism "$@"
CLI
chmod 0755 /usr/local/bin/photoprism-cli

echo '[5/5] services'
cat > /etc/systemd/system/photoprism.service <<'UNIT'
[Unit]
Description=PhotoPrism (natif, LXC)
After=network.target

[Service]
Type=simple
User=photoprism
Group=photoprism
EnvironmentFile=/etc/photoprism/photoprism.env
WorkingDirectory=/var/lib/photoprism
ExecStart=/opt/photoprism/bin/photoprism start
Restart=on-failure
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/photoprism-index.service <<'UNIT'
[Unit]
Description=PhotoPrism incremental index (picks up Nextcloud-synced photos)
After=photoprism.service
Requires=photoprism.service

[Service]
Type=oneshot
User=photoprism
Group=photoprism
EnvironmentFile=/etc/photoprism/photoprism.env
ExecStart=/opt/photoprism/bin/photoprism index
UNIT
cat > /etc/systemd/system/photoprism-index.timer <<'UNIT'
[Unit]
Description=Run PhotoPrism index every 15 min

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable photoprism.service photoprism-index.timer
systemctl restart photoprism.service
systemctl start photoprism-index.timer
echo '=== PhotoPrism (natif) install complete ==='
INNER
)"
}

verify() {
    log "Verifying PhotoPrism on $LXC_IP:$HTTP_PORT ..."
    for _ in $(seq 1 30); do
        curl -fsS -o /dev/null --max-time 3 "http://$LXC_IP:$HTTP_PORT/" && { log "OK — responding."; return 0; }
        sleep 2
    done
    log "WARN: not responding yet (first boot can take a while; check 'photoprismctl logs')."
}

mark_provisioned() { date -Iseconds > "$SENTINEL"; }

main() {
    require_cmds
    ensure_dirs
    ensure_bridge
    ensure_masquerade
    create_lxc
    write_lxc_config
    start_lxc
    wait_for_network
    ensure_resolv
    install_photoprism_in_lxc
    verify
    mark_provisioned
    log "Done — LXC '$LXC_NAME' at $LXC_IP, PhotoPrism running."
    # Jamais le mot de passe lui-même dans la sortie (#1729).
    log "Admin: admin — mot de passe dans $SECRETS_DIR/photoprism-admin (0600) ; à changer par l'interface."
    log "Public (wire HAProxy SNI + nginx vhost): https://$PUBLIC_HOSTNAME/"
    log "Nextcloud side: enable the 'PhotoLibrary' external-storage mount → $SHARED_PHOTOS (secubox-nextcloud)."
}

main "$@"
