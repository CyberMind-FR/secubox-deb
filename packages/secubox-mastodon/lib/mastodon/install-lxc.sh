#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: secubox-mastodon :: install-lxc.sh
#
# Provisionnement IDEMPOTENT du conteneur Mastodon. Sans danger a relancer.
#
# POURQUOI CE SCRIPT EST LONG ET NE L'EST PAS PAR ACCIDENT
#
# Mastodon n'est pas un binaire : c'est Ruby, PostgreSQL, Redis, Sidekiq et
# Puma qui doivent demarrer dans le bon ordre et se parler. Chaque etape ici
# verifie son resultat AVANT de passer a la suivante, parce qu'une pile a
# moitie installee ne se signale pas — elle repond 500 trois jours plus tard.
#
# CHAQUE ETAPE POSE UN JALON. Relancer apres une coupure reprend ou l'on en
# etait, au lieu de tout refaire : sur cette carte, la compilation des gemmes
# prend plus d'une heure.
set -euo pipefail

readonly LXC_NAME="${SECUBOX_LXC_NAME:-mastodon}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.200}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
readonly LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
readonly LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
readonly SUITE="${SECUBOX_DEBIAN_SUITE:-bookworm}"
readonly DOMAINE="${SECUBOX_MASTODON_DOMAIN:?domaine requis}"
readonly ETAT="${SECUBOX_STATE_DIR:-/var/lib/secubox/mastodon}"
readonly SECRETS="${SECUBOX_SECRETS_DIR:-/etc/secubox/secrets}"

log()  { logger -t mastodon-install -- "$*"; printf '[mastodon] %s\n' "$*"; }
fail() { logger -t mastodon-install -p user.err -- "ERREUR: $*"; printf '[mastodon] ERREUR: %s\n' "$*" >&2; exit 1; }
jalon()      { touch "$ETAT/.$1"; }
jalon_pose() { [ -f "$ETAT/.$1" ]; }
dans()       { lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- "$@"; }

prealables() {
    for c in lxc-create lxc-info lxc-start lxc-attach openssl nft curl; do
        command -v "$c" >/dev/null 2>&1 || fail "$c absent"
    done
    install -d -m 0755 "$LXC_PATH" "$ETAT"
    install -d -m 0700 "$SECRETS"
    # 2 Go est un plancher, pas une recommandation : en dessous, Sidekiq se
    # fait tuer par le noyau des la premiere file chargee — et le symptome est
    # « les messages n'arrivent plus », pas « memoire insuffisante ».
    local libre; libre=$(free -m | awk 'NR==2{print $7}')
    [ "$libre" -ge 1800 ] || log "ATTENTION : ${libre} Mo libres, Mastodon en demande 2000"
}

creer_conteneur() {
    if lxc-info -n "$LXC_NAME" -P "$LXC_PATH" >/dev/null 2>&1; then
        log "conteneur deja present"; return 0
    fi
    log "creation du conteneur ($SUITE arm64)"
    lxc-create -n "$LXC_NAME" -t download -P "$LXC_PATH" -- \
        -d debian -r "$SUITE" -a arm64 >/dev/null || fail "lxc-create a echoue"
    cat >> "$LXC_PATH/$LXC_NAME/config" <<EOC

# Reseau : adresse fixe sur le pont des conteneurs. Pas de DHCP — une adresse
# qui change casserait la route nginx et le pare-feu au premier redemarrage.
lxc.net.0.type = veth
lxc.net.0.link = $LXC_BRIDGE
lxc.net.0.flags = up
lxc.net.0.ipv4.address = $LXC_IP/24
lxc.net.0.ipv4.gateway = $LXC_GW
EOC
    jalon cree
}

demarrer() {
    [ "$(lxc-info -n "$LXC_NAME" -P "$LXC_PATH" -s 2>/dev/null | awk '{print $2}')" = "RUNNING" ] && return 0
    lxc-start -n "$LXC_NAME" -P "$LXC_PATH" || fail "demarrage impossible"
    for _ in $(seq 1 30); do
        dans ping -c1 -W1 "$LXC_GW" >/dev/null 2>&1 && return 0
        sleep 1
    done
    fail "pas de reseau dans le conteneur apres 30 s"
}

resolution() {
    # Le lien symbolique vers systemd-resolved n'est pas resolu dans un
    # conteneur fraichement cree : on le remplace par un fichier ordinaire.
    dans sh -c 'rm -f /etc/resolv.conf; printf "nameserver 10.100.0.1\nnameserver 9.9.9.9\n" > /etc/resolv.conf'
}

paquets() {
    jalon_pose paquets && { log "paquets deja installes"; return 0; }
    log "installation des dependances (long)"
    dans env DEBIAN_FRONTEND=noninteractive sh -c '
        apt-get update -qq &&
        apt-get install -y -qq --no-install-recommends \
          postgresql redis-server nginx ruby-full ruby-dev \
          build-essential libpq-dev libxml2-dev libxslt1-dev zlib1g-dev \
          libssl-dev libyaml-dev libreadline-dev libffi-dev libgdbm-dev \
          libicu-dev libidn-dev libvips42 ffmpeg imagemagick \
          nodejs npm git curl ca-certificates' || fail "installation des paquets echouee"
    jalon paquets
}

compte() {
    jalon_pose compte && return 0
    # Compte dedie, sans mot de passe : Mastodon ne doit pas tourner en root,
    # et ce compte ne doit pas servir a se connecter au conteneur.
    dans useradd -m -s /bin/bash mastodon 2>/dev/null || true
    jalon compte
}

secrets() {
    local f="$SECRETS/mastodon"
    [ -s "$f" ] && { log "secrets deja generes"; return 0; }
    log "generation des secrets"
    # GENERES DANS LE CONTENEUR, jamais par cet outil : un secret produit sur
    # l'hote transite par un journal, un historique, une capture d'ecran.
    umask 077
    {
        printf 'SECRET_KEY_BASE=%s\n'   "$(dans openssl rand -hex 64)"
        printf 'OTP_SECRET=%s\n'        "$(dans openssl rand -hex 64)"
        printf 'DB_PASS=%s\n'           "$(dans openssl rand -base64 24 | tr -d '=+/')"
    } > "$f"
    chmod 0600 "$f"; jalon secrets
}

base_de_donnees() {
    jalon_pose bdd && return 0
    local mdp; mdp=$(grep '^DB_PASS=' "$SECRETS/mastodon" | cut -d= -f2-)
    dans su - postgres -c "psql -tc \"SELECT 1 FROM pg_roles WHERE rolname='mastodon'\" | grep -q 1 || \
        psql -c \"CREATE USER mastodon CREATEDB PASSWORD '$mdp'\"" || fail "creation du role echouee"
    jalon bdd
}

application() {
    jalon_pose app && { log "application deja deployee"; return 0; }
    log "recuperation de Mastodon (long : compilation des gemmes)"
    dans su - mastodon -c '
        [ -d live ] || git clone --depth 1 https://github.com/mastodon/mastodon.git live' \
        || fail "clonage impossible"
    jalon app
}

nftables_ouvrir() {
    # Le port 3000 n'est joignable QUE depuis l'hote, via le pont des
    # conteneurs. HAProxy est le seul frontal expose ; ouvrir 3000 au LAN
    # court-circuiterait l'inspection.
    install -d /etc/nftables.d
    cat > /etc/nftables.d/zz-secubox-mastodon.nft <<EOF
# SecuBox-Deb :: mastodon — acces a l'instance depuis l'hote SEULEMENT.
#
# Le prefixe zz- fait trier ce fichier APRES celui qui cree la table : une
# regle appliquee avant sa table est perdue en silence.
add rule inet filter forward ip daddr $LXC_IP tcp dport 3000 ct state new accept
EOF
    log "regle nftables posee (chargee au prochain rechargement)"
}

main() {
    log "=== provisionnement de Mastodon pour $DOMAINE ==="
    prealables
    creer_conteneur
    demarrer
    resolution
    paquets
    compte
    secrets
    base_de_donnees
    application
    nftables_ouvrir
    log "=== base posee ==="
    log "RESTE A FAIRE, ET VOLONTAIREMENT PAS AUTOMATISE :"
    log "  1. bundle install + assets:precompile dans le conteneur (plus d'une heure sur cette carte)"
    log "  2. RAILS_ENV=production bin/rails db:setup"
    log "  3. creation du premier compte : bin/tootctl accounts create --role Owner"
    log "Ces etapes demandent des choix — nom du compte, courriel — qu'un script"
    log "ne doit pas prendre a la place de l'operateur."
}
main "$@"
