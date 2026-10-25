#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: secubox-meet :: install-lxc.sh
#
# Provisionnement idempotent du LXC de La Suite Meet (relançable sans risque).
# Même squelette que secubox-jitsi/lib/jitsi/install-lxc.sh :
#   1. pont br-lxc + MASQUERADE 10.100.0.0/24
#   2. lxc-create -t download (non privilégié, idmap 0 -> 100000), Debian trixie
#   3. configuration LXC rendue par rendu.sh, rootfs décalé sur l'idmap
#   4. installation NATIVE dans le conteneur : postgresql, redis, nginx, backend
#      Django (uv), frontend React (npm), LiveKit (binaire vérifié par SHA-256)
#
# Contrairement à Jitsi (paquets apt), Meet n'a pas de dépôt apt : il est
# construit depuis l'étiquette amont figée dans meet.version, dont le COMMIT est
# vérifié après le clonage (une étiquette amont peut être déplacée).
#
# SECUBOX_MEET_DRY_RUN=<dossier> : rend les fichiers puis sort 0 AVANT tout appel
# lxc-*, sans toucher au pont ni aux pare-feux (utilisé par les tests).
#
# SECUBOX_MEET_RENDRE_SEULEMENT=1 : nouveau rendu seul (meetctl, secret OIDC
# renouvelé) : ni pont, ni pare-feu, ni création, ni construction ; installe les
# configurations dans le conteneur DÉMARRÉ et ne relance que les services dont
# une entrée a changé.

# Les variables posées ici (secrets, domaines) sont lues par rendu.sh.
# shellcheck disable=SC2034
set -euo pipefail

readonly LXC_NAME="${SECUBOX_LXC_NAME:-meet}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.195}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
readonly LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
readonly LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
readonly DEBIAN_SUITE="${SECUBOX_DEBIAN_SUITE:-trixie}"
readonly STATE_DIR="${SECUBOX_MEET_STATE_DIR:-/etc/secubox/meet}"
readonly SECRETS_DIR="${SECUBOX_MEET_SECRETS_DIR:-/etc/secubox/secrets/meet}"
readonly VERSION_FILE="${SECUBOX_MEET_VERSION_FILE:-/usr/share/doc/secubox-meet/examples/meet.version}"
readonly DRY_RUN="${SECUBOX_MEET_DRY_RUN:-}"
readonly RENDRE_SEULEMENT="${SECUBOX_MEET_RENDRE_SEULEMENT:-0}"
readonly SENTINEL="$STATE_DIR/.lxc-provisioned"
readonly DOMAIN_FILE="$STATE_DIR/domaine"

# Noms dérivés du domaine de CETTE box, jamais d'un nom en dur.
MEET_DOMAIN="${SECUBOX_MEET_DOMAIN:-$(secubox-domaine visio 2>/dev/null || true)}"
LIVEKIT_DOMAIN="${SECUBOX_LIVEKIT_DOMAIN:-$(secubox-domaine livekit 2>/dev/null || true)}"

log()  { printf '[meet-install] %s\n' "$*"; }
fail() { printf '[meet-install] ERREUR : %s\n' "$*" >&2; exit 1; }

# shellcheck source-path=SCRIPTDIR source=rendu.sh
. "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/rendu.sh"

require_cmds() {
    local c
    for c in lxc-create lxc-info lxc-start lxc-attach nft openssl; do
        command -v "$c" >/dev/null 2>&1 || fail "$c n'est pas installé"
    done
}

# Versions figées : MEET_TAG MEET_COMMIT LIVEKIT_VERSION LIVEKIT_SHA256_{ARM64,AMD64}.
charger_versions() {
    [ -r "$VERSION_FILE" ] || fail "fichier de versions illisible : $VERSION_FILE"
    # shellcheck source=/dev/null
    . "$VERSION_FILE"
    local arch; arch="$(dpkg --print-architecture)"
    case "$arch" in
        arm64) LIVEKIT_SHA256="${LIVEKIT_SHA256_ARM64:-}" ;;
        amd64) LIVEKIT_SHA256="${LIVEKIT_SHA256_AMD64:-}" ;;
        *)     LIVEKIT_SHA256="" ;;
    esac
    [ -n "$LIVEKIT_SHA256" ] || fail "somme SHA-256 de LiveKit absente pour l'architecture $arch (meet.version)"
    if [ -z "${MEET_TAG:-}" ] || [ -z "${MEET_COMMIT:-}" ] || [ -z "${LIVEKIT_VERSION:-}" ]; then
        fail "meet.version incomplet (MEET_TAG, MEET_COMMIT, LIVEKIT_VERSION)"
    fi
}

# Secret créé UNE fois (0600, dossier 0700) puis relu à chaque passe : le
# régénérer casserait la base (mot de passe) et les sessions (clé Django).
secret() {
    local longueur="$2" f="$SECRETS_DIR/$1"
    install -d -m 0700 "$SECRETS_DIR"
    if [ ! -s "$f" ]; then
        ( umask 077
          openssl rand -base64 96 | tr -d '/+=\n' | head -c "$longueur" > "$f" )
    fi
    chmod 0600 "$f"
    cat "$f"
}

# Client OIDC : enregistré par meetctl (même hôte) AVANT le rendu, pour que
# meet.env porte le secret dès la première passe. Un échec arrête tout. En essai
# à blanc, seul un SECUBOX_MEETCTL explicite (faux des tests) est appelé : le
# vrai secubox-oidcctl exige root et le fournisseur de la box.
# SECUBOX_MEET_APPLIQUER=0 : ce script rend et applique lui-même, meetctl ne
# relance donc pas un rendu imbriqué.
enregistrer_client_oidc() {
    [ -n "$DRY_RUN" ] && [ -z "${SECUBOX_MEETCTL:-}" ] && return 0
    log "Enregistrement du client OIDC « meet » ..."
    SECUBOX_MEET_APPLIQUER=0 SECUBOX_MEET_DOMAIN="$MEET_DOMAIN" "${SECUBOX_MEETCTL:-/usr/sbin/meetctl}" oidc-enregistrer >/dev/null \
        || fail "enregistrement du client OIDC impossible (meetctl oidc-enregistrer)"
    [ -s "$SECRETS_DIR/oidc-client-secret" ] \
        || fail "client OIDC enregistré mais secret absent ou vide ($SECRETS_DIR/oidc-client-secret)"
}

preparer_secrets() {
    DJANGO_SECRET_KEY="$(secret django-secret 50)"
    DB_PASSWORD="$(secret db-password 32)"
    LIVEKIT_SECRET="$(secret livekit-secret 32)"
    enregistrer_client_oidc
    OIDC_CLIENT_SECRET=""
    [ -s "$SECRETS_DIR/oidc-client-secret" ] && OIDC_CLIENT_SECRET="$(cat "$SECRETS_DIR/oidc-client-secret")"
    # Émetteur OIDC = le Hall de la box : domaine de Meet sans son premier nom.
    MEET_ISSUER="${MEET_ISSUER:-https://hall.${MEET_DOMAIN#*.}/oidc}"
}

ensure_dirs() {
    # Dossier commun à tous les conteneurs de la box : créé s'il manque, jamais réimposé.
    [ -d "$LXC_PATH" ] || install -d -m 0755 -o root -g root "$LXC_PATH"
    install -d -m 0755 -o root -g root "$STATE_DIR"
    install -d -m 0700 -o root -g root "$SECRETS_DIR"
}

ensure_bridge() {
    if ! ip link show "$LXC_BRIDGE" >/dev/null 2>&1; then
        log "Création du pont $LXC_BRIDGE @ ${LXC_GW}/24 ..."
        ip link add name "$LXC_BRIDGE" type bridge
        ip addr add "${LXC_GW}/24" dev "$LXC_BRIDGE"
        ip link set "$LXC_BRIDGE" up
    elif ! ip -4 -br addr show dev "$LXC_BRIDGE" 2>/dev/null \
            | awk -v a="${LXC_GW}/24" '{ for (i = 3; i <= NF; i++) if ($i == a) ok = 1 } END { exit !ok }'; then
        # Pont présent sans la passerelle des conteneurs (absent du netplan, son
        # adresse perdue au redémarrage) : le conteneur attendrait 30 s un réseau
        # qui ne viendra pas. On le dit tout de suite.
        fail "$LXC_BRIDGE n'a pas l'adresse ${LXC_GW}/24 : déclarez-le dans le netplan (secubox-net-detect apply ou /etc/netplan) — #3162"
    fi
}

ensure_masquerade() {
    if ! nft list table ip lxc 2>/dev/null | grep -q 'saddr 10.100.0.0/24'; then
        log "Ajout du MASQUERADE nftables pour 10.100.0.0/24 ..."
        nft 'add table ip lxc' 2>/dev/null || true
        nft 'add chain ip lxc postrouting { type nat hook postrouting priority srcnat ; policy accept ; }' 2>/dev/null || true
        nft 'add rule ip lxc postrouting ip saddr 10.100.0.0/24 ip daddr != 10.100.0.0/24 counter masquerade' 2>/dev/null || true
    fi
}

lxc_state() {
    lxc-info -n "$LXC_NAME" -P "$LXC_PATH" 2>/dev/null \
        | awk -F: '/^State:/ { gsub(/ /,"",$2); print tolower($2) }' || true
}

# Une création interrompue laisse un répertoire avec un marqueur `partial` sur
# lequel lxc-start refuse ensuite de démarrer (« Ongoing container creation
# detected »), indéfiniment. On teste ce marqueur, pas une heuristique.
clean_partial_lxc() {
    local dir="$LXC_PATH/$LXC_NAME"
    [ -d "$dir" ] || return 0
    if [ ! -e "$dir/partial" ] && [ -f "$dir/config" ] && [ -d "$dir/rootfs" ]; then
        return 0
    fi
    log "Reliquat de création détecté ($dir) : nettoyage avant nouvelle tentative"
    lxc-destroy -n "$LXC_NAME" -P "$LXC_PATH" -f 2>/dev/null || rm -rf "$dir"
}

create_lxc() {
    clean_partial_lxc
    if [ -d "$LXC_PATH/$LXC_NAME/rootfs" ]; then
        log "LXC '$LXC_NAME' existe déjà : pas de nouvelle création"
        return
    fi
    log "Création du LXC non privilégié '$LXC_NAME' (debian $DEBIAN_SUITE) ..."
    lxc-create -n "$LXC_NAME" -t download -P "$LXC_PATH" \
        -- --dist debian --release "$DEBIAN_SUITE" \
           --arch "$(dpkg --print-architecture)"
}

write_lxc_config() {
    log "Configuration du conteneur : $LXC_IP/24 sur $LXC_BRIDGE (idmap 0->100000)"
    install -m 0644 "$RENDU_DIR/lxc-config" "$LXC_PATH/$LXC_NAME/config"

    # Décaler la propriété du rootfs sur l'idmap : `lxc-create -t download`
    # déballe en uid 0 de l'HÔTE, or le conteneur s'attend à l'uid 100000. Sans
    # cela lxc-start échoue sur « Failed to setup rootfs » sans nommer l'idmap
    # (#1308). On ne décale que si la racine est encore à l'uid 0.
    if [ -d "$LXC_PATH/$LXC_NAME/rootfs" ] \
       && [ "$(stat -c %u "$LXC_PATH/$LXC_NAME/rootfs")" = "0" ]; then
        log "Décalage de la propriété du rootfs sur l'idmap (0 -> 100000) ..."
        chown -R 100000:100000 "$LXC_PATH/$LXC_NAME/rootfs"
        chown 100000:100000 "$LXC_PATH/$LXC_NAME"
    fi
}

# Pose la configuration réseau fixe dans le rootfs (propriété décalée sur l'idmap) avant le démarrage ; si le
# conteneur tourne déjà (reprise d'un provisionnement), networkd la relit et reconfigure eth0 tout de suite.
ecrire_reseau_conteneur() {
    local dossier="$LXC_PATH/$LXC_NAME/rootfs/etc/systemd/network"
    [ -d "$dossier" ] || return 0   # image sans systemd-networkd : la configuration LXC suffit
    log "Réseau fixe du conteneur : ${LXC_IP}/24 via ${LXC_GW}"
    install -m 0644 "$RENDU_DIR/conteneur-eth0.network" "$dossier/eth0.network"
    chown 100000:100000 "$dossier/eth0.network"
    if [ "$(lxc_state)" = "running" ]; then
        lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- networkctl reload || true
        lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- networkctl reconfigure eth0 || true
    fi
}

start_lxc() {
    [ "$(lxc_state)" = "running" ] && { log "Déjà démarré"; return; }
    log "Démarrage du LXC '$LXC_NAME' ..."
    lxc-start -n "$LXC_NAME" -P "$LXC_PATH"
}

wait_for_network() {
    log "Attente du réseau du conteneur ..."
    local _
    for _ in $(seq 1 30); do
        lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- ping -c1 -W1 "$LXC_GW" >/dev/null 2>&1 && return 0
        sleep 1
    done
    fail "le LXC '$LXC_NAME' n'a pas joint $LXC_GW en 30 s"
}

ensure_resolv() {
    log "Écriture de /etc/resolv.conf dans le conteneur ..."
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- sh -c '
        rm -f /etc/resolv.conf
        printf "nameserver 1.1.1.1\nnameserver 9.9.9.9\n" > /etc/resolv.conf
    '
}

# Dépose les fichiers rendus dans le rootfs (propriété décalée sur l'idmap),
# d'où le script interne les installe. Le dossier contient des secrets : 0700,
# supprimé dès la fin.
deposer_rendu() {
    local cible="$LXC_PATH/$LXC_NAME/rootfs/root/meet-rendu"
    rm -rf "$cible"
    install -d -m 0700 "$cible"
    cp "$RENDU_DIR"/{livekit.yaml,meet.env,nginx-meet.conf,meet-backend.service,livekit.service} "$cible/"
    chown -R 100000:100000 "$cible"
}

retirer_rendu() { rm -rf "$LXC_PATH/$LXC_NAME/rootfs/root/meet-rendu"; }

# Script exécuté DANS le conteneur. Passé par `bash -e -c` (et non par stdin)
# pour que apt, git, npm et psql ne consomment pas le script en le lisant.
# Idempotent : chaque étape se saute si son résultat est déjà là.
# Les variables de version arrivent par l'environnement ; aucun secret n'y
# passe (le mot de passe de la base est relu dans /etc/meet/meet.env).
# RENDRE_SEULEMENT=1 : seulement les configurations rendues et la relance.
SCRIPT_INTERNE=$(cat <<'INNER'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export UV_PROJECT_ENVIRONMENT=/opt/meet/venv
# uv n'ira jamais chercher un interpréteur sur le réseau : le python3 de Debian fait foi.
export UV_PYTHON_DOWNLOADS=never
RENDRE_SEULEMENT="${RENDRE_SEULEMENT:-0}"

# Entrées de chaque service (chemins sans espace). `systemctl enable --now` ne
# relance pas une unité déjà active : sans la comparaison qui suit, un nouveau
# secret, une nouvelle configuration ou un nouveau code n'atteindraient jamais
# les services.
UNITES="/etc/systemd/system/meet-backend.service /etc/systemd/system/livekit.service"
ENTREES_BACKEND="/etc/meet/meet.env /etc/systemd/system/meet-backend.service /opt/meet/.construit-$MEET_COMMIT"
ENTREES_LIVEKIT="/etc/livekit/livekit.yaml /etc/systemd/system/livekit.service /usr/local/bin/.livekit-$LIVEKIT_VERSION"
ENTREES_NGINX="/etc/nginx/sites-enabled/meet"

# Empreinte (sha256) d'un fichier, « absent » s'il n'existe pas.
empreinte() {
    if [ -e "$1" ]; then sha256sum < "$1" | cut -d' ' -f1; else echo absent; fi
}

# Photographie : une ligne « empreinte chemin » par fichier.
photo() {
    local f
    for f in "$@"; do printf '%s %s\n' "$(empreinte "$f")" "$f"; done
}

# change <photo> <fichier>... : vrai si l'un des fichiers diffère de la photo.
change() {
    local avant="$1" f
    shift
    for f in "$@"; do
        grep -qxF -- "$(empreinte "$f") $f" <<<"$avant" || return 0
    done
    return 1
}

# Photo du dernier état appliqué aux services, notée seulement une fois tout
# relancé. Une passe qui échoue entre la pose des fichiers et la relance laisse
# l'ancienne photo : la suivante relance (gk1 : nginx, démarré par son paquet sur
# le site par défaut, n'était jamais rechargé). Sans photo, tout est relancé.
PHOTO_APPLIQUEE=/etc/meet/.photo-appliquee

photo_appliquee() {
    cat "$PHOTO_APPLIQUEE" 2>/dev/null || true
}

noter_applique() {
    ( umask 077; photo $ENTREES_BACKEND $ENTREES_LIVEKIT $ENTREES_NGINX > "$PHOTO_APPLIQUEE.tmp" )
    mv "$PHOTO_APPLIQUEE.tmp" "$PHOTO_APPLIQUEE"
}

# Relance les SEULS services dont une entrée a changé depuis la photo. Un
# service arrêté n'est pas démarré ici (try-*) : `enable --now` s'en charge.
relancer_si_change() {
    local avant="$1"
    if change "$avant" $UNITES; then systemctl daemon-reload; fi
    if change "$avant" $ENTREES_BACKEND; then systemctl try-restart meet-backend; fi
    if change "$avant" $ENTREES_LIVEKIT; then systemctl try-restart livekit; fi
    if change "$avant" $ENTREES_NGINX; then
        nginx -t
        systemctl try-reload-or-restart nginx
    fi
}

# Paquets, comptes, sources, construction, LiveKit (sautés en rendu seul).
construire() {
    apt-get update -q
    apt-get install -y --no-install-recommends \
        postgresql redis-server nginx python3 python3-venv nodejs npm git \
        ca-certificates curl libmagic1 libpango-1.0-0 gettext
    # L'unité Debian de redis-server porte PrivateUsers=true : refusé dans un conteneur LXC non privilégié
    # (« Failed to set up user namespacing », 217/USER, gk1). LiveKit et le cache de Meet en dépendent.
    install -d -m 0755 /etc/systemd/system/redis-server.service.d
    printf '[Service]\nPrivateUsers=no\n' > /etc/systemd/system/redis-server.service.d/10-secubox-lxc.conf
    systemctl daemon-reload
    systemctl reset-failed redis-server 2>/dev/null || true

    id meet >/dev/null 2>&1 || useradd --system --home-dir /var/lib/meet --shell /usr/sbin/nologin meet
    id livekit >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin livekit
    # 0751 : nginx (www-data) doit traverser jusqu'à /var/lib/meet/static.
    install -d -o meet -g meet -m 0751 /var/lib/meet
    install -d -m 0755 /opt/meet /etc/meet /etc/livekit

    # Sources : étiquette figée, puis commit vérifié (une étiquette peut être déplacée).
    if [ "$(git -C /opt/meet/src rev-parse HEAD 2>/dev/null || true)" != "$MEET_COMMIT" ]; then
        rm -rf /opt/meet/src /opt/meet/.construit-*
        git clone --depth 1 --branch "$MEET_TAG" https://github.com/suitenumerique/meet.git /opt/meet/src
        [ "$(git -C /opt/meet/src rev-parse HEAD)" = "$MEET_COMMIT" ] \
            || { echo "commit inattendu pour $MEET_TAG : refus" >&2; rm -rf /opt/meet/src; exit 1; }
    fi

    if [ ! -e "/opt/meet/.construit-$MEET_COMMIT" ]; then
        [ -x /opt/meet/venv/bin/python ] || python3 -m venv /opt/meet/venv
        # uv vit dans son propre venv : `uv sync --locked` est exact et retirerait
        # pip/uv du venv de Meet, ce qui casserait toute relance après un échec.
        [ -x /opt/meet/uv-venv/bin/uv ] || {
            python3 -m venv /opt/meet/uv-venv
            /opt/meet/uv-venv/bin/pip install --quiet uv
        }
        ( cd /opt/meet/src/src/backend && /opt/meet/uv-venv/bin/uv sync --locked --no-dev )
        ( cd /opt/meet/src/src/frontend && npm ci --ignore-scripts && npm run build )
        rm -rf /opt/meet/frontend
        cp -r /opt/meet/src/src/frontend/dist /opt/meet/frontend
    fi

    # LiveKit : binaire téléchargé, somme SHA-256 vérifiée AVANT installation.
    if [ ! -e "/usr/local/bin/.livekit-$LIVEKIT_VERSION" ]; then
        local tmp archive
        tmp=$(mktemp -d)
        archive="livekit_${LIVEKIT_VERSION}_linux_${ARCH}.tar.gz"
        curl -fsSL -o "$tmp/$archive" \
            "https://github.com/livekit/livekit/releases/download/v${LIVEKIT_VERSION}/$archive"
        ( cd "$tmp" && echo "$LIVEKIT_SHA256  $archive" | sha256sum -c - )
        tar -xzf "$tmp/$archive" -C "$tmp" livekit-server
        install -m 0755 "$tmp/livekit-server" /usr/local/bin/livekit-server
        touch "/usr/local/bin/.livekit-$LIVEKIT_VERSION"
        rm -rf "$tmp"
    fi
}

# Configurations rendues par l'hôte.
installer_configs() {
    local rendu=/root/meet-rendu
    install -m 0640 -o root -g meet "$rendu/meet.env" /etc/meet/meet.env
    install -m 0640 -o root -g livekit "$rendu/livekit.yaml" /etc/livekit/livekit.yaml
    install -m 0644 "$rendu/nginx-meet.conf" /etc/nginx/sites-enabled/meet
    rm -f /etc/nginx/sites-enabled/default
    install -m 0644 "$rendu/meet-backend.service" /etc/systemd/system/meet-backend.service
    install -m 0644 "$rendu/livekit.service" /etc/systemd/system/livekit.service
}

# manage.py avec l'environnement de l'unité (meet.env n'est pas du shell valide :
# `["name"]` y serait déformé), donc via systemd-run et son EnvironmentFile.
manage() {
    systemd-run --quiet --wait --pipe -p "User=${MANAGE_USER:-meet}" -p EnvironmentFile=/etc/meet/meet.env \
        -p WorkingDirectory=/opt/meet/src/src/backend /opt/meet/venv/bin/python manage.py "$@"
}

# Base et Django (sautés en rendu seul) : le rôle est créé une fois, le mot de
# passe réaligné à chaque passe ; migrations, statiques, traductions.
preparer_base() {
    systemctl enable --now postgresql redis-server
    local db_pw
    db_pw=$(sed -n 's/^DB_PASSWORD=//p' /etc/meet/meet.env)
    runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='meet'" | grep -q 1 \
        || runuser -u postgres -- createuser meet
    runuser -u postgres -- psql -v ON_ERROR_STOP=1 -q <<SQL
ALTER ROLE meet PASSWORD '$db_pw';
SQL
    runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname='meet'" | grep -q 1 \
        || runuser -u postgres -- createdb -O meet meet

    manage migrate --noinput
    manage collectstatic --noinput
    chmod 0755 /var/lib/meet/static
    # En root : les sources ont été clonées par root, `meet` ne peut pas écrire
    # dans locale/ (sinon échec définitif, relancé toutes les 15 min).
    MANAGE_USER=root manage compilemessages
    touch "/opt/meet/.construit-$MEET_COMMIT"
}

if [ "$RENDRE_SEULEMENT" != 1 ]; then construire; fi
installer_configs
if [ "$RENDRE_SEULEMENT" != 1 ]; then preparer_base; fi
relancer_si_change "$(photo_appliquee)"
systemctl enable --now postgresql redis-server livekit meet-backend nginx
noter_applique
INNER
)

install_in_lxc() {
    log "Installation de Meet dans '$LXC_NAME' (domaine : $MEET_DOMAIN) ..."
    if [ -s "$DOMAIN_FILE" ] && [ "$(cat "$DOMAIN_FILE")" != "$MEET_DOMAIN" ]; then
        log "Le domaine a changé : nouveau rendu, relance des services concernés (les salles sont conservées)"
    fi
    deposer_rendu
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- env \
        "MEET_TAG=$MEET_TAG" "MEET_COMMIT=$MEET_COMMIT" \
        "LIVEKIT_VERSION=$LIVEKIT_VERSION" "LIVEKIT_SHA256=$LIVEKIT_SHA256" \
        "ARCH=$(dpkg --print-architecture)" "RENDRE_SEULEMENT=$RENDRE_SEULEMENT" \
        bash -e -c "$SCRIPT_INTERNE"
    retirer_rendu
}

# Empreinte du secret OIDC que le conteneur vient de recevoir (jamais le secret
# lui-même) : meetctl la compare au secret courant pour savoir s'il reste à
# l'appliquer.
noter_secret_applique() {
    [ -n "$OIDC_CLIENT_SECRET" ] || return 0
    ( umask 077
      printf '%s' "$OIDC_CLIENT_SECRET" | sha256sum | cut -d' ' -f1 > "$SECRETS_DIR/.oidc-applique" )
    chmod 0600 "$SECRETS_DIR/.oidc-applique"
}

mark_provisioned() {
    printf '%s\n' "$MEET_DOMAIN" > "$DOMAIN_FILE"
    date -Is > "$SENTINEL"
    log "Témoin de provisionnement : $SENTINEL"
}

main() {
    require_cmds
    if [ "$RENDRE_SEULEMENT" = 1 ] && [ -z "$DRY_RUN" ]; then
        [ -d "$LXC_PATH/$LXC_NAME/rootfs" ] \
            || fail "conteneur '$LXC_NAME' absent : provisionnement complet requis (meetctl install)"
        [ "$(lxc_state)" = "running" ] \
            || fail "conteneur '$LXC_NAME' à l'arrêt : le rendu seul exige un conteneur démarré"
    fi
    [ -n "$MEET_DOMAIN" ] || fail "domaine de la box inconnu : définir [global] domain, SECUBOX_MEET_DOMAIN ou secubox-domaine"
    [ -n "$LIVEKIT_DOMAIN" ] || fail "domaine LiveKit inconnu (secubox-domaine livekit ou SECUBOX_LIVEKIT_DOMAIN)"
    charger_versions
    preparer_secrets

    RENDU_DIR="${DRY_RUN:-$(mktemp -d)}"
    if [ -z "$DRY_RUN" ]; then
        trap 'rm -rf "$RENDU_DIR" "$LXC_PATH/$LXC_NAME/rootfs/root/meet-rendu"' EXIT
    fi
    rendre_tout "$RENDU_DIR"
    if [ -n "$DRY_RUN" ]; then
        log "Essai à blanc : fichiers rendus dans $DRY_RUN"
        exit 0
    fi

    if [ "$RENDRE_SEULEMENT" = 1 ]; then
        install_in_lxc
        noter_secret_applique
        log "Nouveau rendu appliqué au conteneur (sans construction)."
        return 0
    fi

    ensure_dirs
    ensure_bridge
    ensure_masquerade
    create_lxc
    write_lxc_config
    ecrire_reseau_conteneur
    start_lxc
    wait_for_network
    ensure_resolv
    install_in_lxc
    noter_secret_applique
    mark_provisioned
    log "Terminé. Web interne : http://${LXC_IP}/  -  média : 7881/TCP et 7882/UDP"
    log "Rappel : rediriger 7881/TCP et 7882/UDP de la box vers cet hôte (meetctl media-expose)."
}

main "$@"
