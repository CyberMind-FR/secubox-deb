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
# TRIXIE, ET NON BOOKWORM COMME LES AUTRES MODULES.
#
# Mastodon exige Ruby >= 3.3 ; bookworm livre 3.1.2, et Node 18 la ou il en
# faut 20. Les deux autres voies ont ete ecartees :
#
#   - compiler Ruby depuis les sources (rbenv) : plusieurs heures sur cette
#     carte, et une pile a maintenir a la main a chaque mise a jour ;
#   - installer Ruby de trixie dans un conteneur bookworm : melange de glibc,
#     panne differee et incomprehensible.
#
# Le conteneur est un bac isole : rien n'oblige a lui donner la meme version
# que l'hote. C'est precisement l'interet.
readonly SUITE="${SECUBOX_DEBIAN_SUITE:-trixie}"
# Le domaine vient de l'environnement (quand `mastodonctl` appelle) OU de la
# configuration (quand ce script est lance seul, par systemd-run ou a la main).
# Exiger la variable rendait le script inutilisable hors de son appelant — et
# c'est justement seul qu'on le relance apres une coupure.
_conf_domaine() {
    local f="${SECUBOX_MASTODON_CONF:-/etc/secubox/mastodon.toml}"
    [ -r "$f" ] || return 0
    awk -F= '/^[[:space:]]*domain[[:space:]]*=/{gsub(/[" ]/,"",$2); sub(/#.*/,"",$2); print $2; exit}' "$f"
}
DOMAINE="${SECUBOX_MASTODON_DOMAIN:-$(_conf_domaine)}"
readonly DOMAINE
[ -n "$DOMAINE" ] || { echo "[mastodon] ERREUR: aucun domaine — ni en environnement, ni dans la configuration" >&2; exit 2; }
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
    # ON REMPLACE, ON N'APPEND PAS.
    #
    # `lxc-create -t download` a DEJA ecrit un bloc lxc.net.0. Ajouter le notre
    # a la suite ne le complete ni ne le remplace : LXC ne fusionne pas les
    # deux, l'interface ne recoit AUCUNE adresse, et le conteneur demarre avec
    # seulement `lo`.
    #
    # Le symptome trompe : le conteneur est RUNNING, la passerelle est
    # injoignable, apt echoue sans erreur explicite et l'installation s'arrete
    # sans rien dire. Constate ici meme avant correction.
    sed -i '/^lxc\.net\.0\./d' "$LXC_PATH/$LXC_NAME/config"
    cat >> "$LXC_PATH/$LXC_NAME/config" <<EOC

# Reseau : adresse fixe sur le pont des conteneurs. Pas de DHCP — une adresse
# qui change casserait la route nginx et le pare-feu au premier redemarrage.
lxc.net.0.type = veth
lxc.net.0.link = $LXC_BRIDGE
lxc.net.0.flags = up
# `name` est absent du gabarit et present chez les conteneurs qui marchent :
# sans lui, l'interface peut ne pas s'appeler eth0 dans le conteneur.
lxc.net.0.name = eth0
lxc.net.0.ipv4.address = $LXC_IP/24
lxc.net.0.ipv4.gateway = $LXC_GW
EOC
    jalon cree
}

demarrer() {
    [ "$(lxc-info -n "$LXC_NAME" -P "$LXC_PATH" -s 2>/dev/null | awk '{print $2}')" = "RUNNING" ] && return 0
    lxc-start -n "$LXC_NAME" -P "$LXC_PATH" || fail "demarrage impossible"
    # On attend que l'init reponde, PAS que le reseau marche : l'adresse est
    # posee juste apres par reseau_statique().
    for _ in $(seq 1 30); do
        dans true >/dev/null 2>&1 && return 0
        sleep 1
    done
    # ON DIT CE QUI MANQUE. « pas de reseau » envoie chercher du cote du pont
    # ou du pare-feu ; une interface sans adresse est un probleme de
    # configuration du conteneur, et le distinguer fait gagner une heure.
    fail "l'init du conteneur ne repond pas apres 30 s"
}

# reseau_statique : poser l'adresse DANS le conteneur, pas seulement dans LXC.
#
# Le gabarit de trixie active systemd-networkd avec `DHCP=true`. Il n'y a pas
# de serveur DHCP sur le pont des conteneurs : networkd ECRASE alors l'adresse
# posee par `lxc.net.0.ipv4.address` et n'en obtient aucune.
#
# Le symptome est cruel : le conteneur est RUNNING, eth0 est UP et rattache au
# pont, mais il n'a pas d'adresse et rien ne sort. On cherche du cote du pont,
# du pare-feu, de la translation d'adresses — alors que la configuration du
# conteneur se defait toute seule au demarrage.
#
# bookworm ne se comportait pas ainsi : ce n'est pas une regression du script,
# c'est une difference de distribution, et elle se reglera de la meme facon
# pour tout module qui passera a trixie.
reseau_statique() {
    dans sh -c "cat > /etc/systemd/network/eth0.network <<EOC
[Match]
Name=eth0

[Network]
Address=$LXC_IP/24
Gateway=$LXC_GW
DNS=$LXC_GW
DNS=9.9.9.9
EOC
systemctl restart systemd-networkd 2>/dev/null || true"
    for _ in $(seq 1 15); do
        dans ip -4 addr show eth0 2>/dev/null | grep -q "inet " && return 0
        sleep 1
    done
    fail "eth0 reste sans adresse malgre la configuration statique"
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
    # Sans cela, toute commande git lancee par un autre compte refuse de lire
    # le depot (« dubious ownership ») — et le message n'indique pas que c'est
    # le PROPRIETAIRE qui gene, pas les droits.
    dans git config --global --add safe.directory /home/mastodon/live 2>/dev/null || true
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
    reseau_statique
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
