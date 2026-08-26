#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: mail :: install + configure helpers for the single mail LXC.
# Extracted in Phase 1 from packages/secubox-mail/sbin/{mailserverctl,roundcubectl}.
# Sourced library — do not execute directly.
#
# All functions take the container name as $1. They read defaults from the
# environment ($LXC_BASE, $DATA_PATH, $DOMAIN, $HOSTNAME, $WEBMAIL_PORT) so
# the same helpers work from mailctl, mail-migrate-to-single-lxc.sh, and
# the bats suite (which overrides $LXC_BASE/$DATA_PATH to a tmpdir).

# Bootstrap a fresh Debian bookworm rootfs into ${LXC_BASE}/${container}/rootfs.
# Idempotent: safe to skip if rootfs already exists.
bootstrap_debian() {
    local container="$1"
    local base="${LXC_BASE:-/var/lib/lxc}"
    local lxc_path="$base/$container"

    mkdir -p "$lxc_path"
    if [ -d "$lxc_path/rootfs/etc" ]; then
        echo "[install] rootfs already present at $lxc_path/rootfs — skipping debootstrap"
        return 0
    fi

    if ! command -v debootstrap >/dev/null 2>&1; then
        echo "ERROR: debootstrap not installed. Run: apt install debootstrap" >&2
        return 1
    fi

    echo "[install] running debootstrap (a few minutes)..."
    debootstrap --variant=minbase --include=ca-certificates,curl,gnupg,locales \
        bookworm "$lxc_path/rootfs" http://deb.debian.org/debian

    echo "$container" > "$lxc_path/rootfs/etc/hostname"
    cat > "$lxc_path/rootfs/etc/resolv.conf" <<'EOF'
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF
    echo "[install] Debian base system installed"
}

# Install Postfix + Dovecot + rsyslog inside the LXC rootfs. Run via chroot
# so the container does not need to be running yet.
install_mail_packages() {
    local container="$1"
    local rootfs="${LXC_BASE:-/var/lib/lxc}/$container/rootfs"

    echo "[install] installing Postfix + Dovecot + Rspamd inside $rootfs..."
    chroot "$rootfs" /bin/bash <<'CHROOT_EOF'
export DEBIAN_FRONTEND=noninteractive
apt-get update
# Phase 2 (rev. 3): mail LXC = MTA + MDA + Rspamd only.
# Apache/Roundcube live in the roundcube LXC; no webmail packages here.
apt-get install -y --no-install-recommends \
    postfix postfix-lmdb \
    dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd \
    dovecot-sieve dovecot-managesieved \
    rspamd redis-server \
    rsyslog ca-certificates openssl

# Redis is the future bayes/ratelimit backend (Phase 8); keep it disabled.
systemctl disable redis-server.service 2>/dev/null || true

groupadd -g 5000 vmail 2>/dev/null || true
useradd -u 5000 -g vmail -s /usr/sbin/nologin -d /var/vmail -M vmail 2>/dev/null || true

# Phase 1 follow-up: ensure Postfix + Dovecot autostart on LXC boot.
systemctl enable postfix dovecot rspamd

apt-get clean
rm -rf /var/lib/apt/lists/*
CHROOT_EOF
    echo "[install] mail packages installed"
}

# Install Apache+PHP+Roundcube inside the same LXC rootfs. Mirrors what the
# legacy roundcubectl::install_roundcube_packages did, but the board reality
# uses Apache+mod_php (not nginx+php-fpm). Phase 5 may reconcile.
install_webmail_packages() {
    local container="$1"
    local rootfs="${LXC_BASE:-/var/lib/lxc}/$container/rootfs"

    echo "[install] installing Roundcube webmail stack inside $rootfs..."
    chroot "$rootfs" /bin/bash <<'CHROOT_EOF'
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    apache2 libapache2-mod-php8.2 \
    php8.2-imap php8.2-ldap php8.2-curl php8.2-xml \
    php8.2-mbstring php8.2-intl php8.2-sqlite3 \
    php8.2-zip php8.2-gd \
    roundcube roundcube-core roundcube-plugins roundcube-sqlite3 \
    roundcube-skin-classic roundcube-skin-larry \
    php-net-sieve \
    sqlite3 \
    ca-certificates curl

apt-get clean
rm -rf /var/lib/apt/lists/*
CHROOT_EOF
    echo "[install] webmail packages installed"
}

# Write Postfix main.cf + master.cf into the LXC rootfs. Reads $HOSTNAME +
# $DOMAIN from the environment; caller (mailctl) supplies them from
# /etc/secubox/mail.toml.
configure_postfix() {
    local container="$1"
    local rootfs="${LXC_BASE:-/var/lib/lxc}/$container/rootfs"
    local hostname="${HOSTNAME:-mail}"
    local domain="${DOMAIN:-secubox.local}"
    echo "[install] configuring Postfix in $rootfs..."

    mkdir -p "$rootfs/etc/postfix"

    cat > "$rootfs/etc/postfix/main.cf" <<EOF
# SecuBox Postfix Configuration
myhostname = ${hostname}.${domain}
mydomain = ${domain}
myorigin = \$mydomain
mydestination = \$myhostname, localhost.\$mydomain, localhost
mynetworks = 127.0.0.0/8 [::1]/128 10.100.0.0/16 192.168.0.0/16 10.0.0.0/8

# Virtual mailbox
virtual_mailbox_domains = ${domain}
virtual_mailbox_base = /var/vmail
virtual_mailbox_maps = lmdb:/etc/mail-config/vmailbox
virtual_alias_maps = lmdb:/etc/mail-config/virtual
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000
virtual_transport = lmtp:unix:private/dovecot-lmtp

# SASL auth via Dovecot
smtpd_sasl_auth_enable = yes
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_security_options = noanonymous
broken_sasl_auth_clients = yes

# TLS
smtpd_tls_cert_file = /etc/ssl/mail/fullchain.pem
smtpd_tls_key_file = /etc/ssl/mail/privkey.pem
smtpd_tls_security_level = may
smtp_tls_security_level = may

# Restrictions
smtpd_recipient_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination
smtpd_sender_restrictions = permit_sasl_authenticated, permit_mynetworks

# Limites de taille : AUCUNE, par decision (#1025).
#
# La board recoit des depots — archives, medias, sauvegardes — et la limite de
# 10 Mo heritee du defaut postfix rejetait un courrier de 31 Mo avec un
# « message size exceeds size limit » cote EXPEDITEUR. Un refus a la porte est
# la pire des places pour une limite : l'emetteur ne sait pas quoi faire de son
# fichier, et le destinataire n'apprend meme pas qu'on a essaye de le joindre.
#
# LES TROIS VONT ENSEMBLE. `virtual_mailbox_limit` borne ce qu'une boite peut
# recevoir : le laisser a 50 Mo avec un message illimite ferait echouer la
# remise APRES l'acceptation — un rejet plus tardif, donc plus obscur, que
# celui qu'on vient de retirer.
#
# La contrepartie est assumee : rien ne borne plus la taille d'un envoi, et
# c'est le disque de /data qui fait office de limite. Sur une machine
# personnelle qui sert aussi de coffre a fichiers, c'est le bon arbitrage.
mailbox_size_limit = 0
message_size_limit = 0
virtual_mailbox_limit = 0
inet_interfaces = all
inet_protocols = ipv4
EOF

    cat > "$rootfs/etc/postfix/master.cf" <<'EOF'
smtp      inet  n       -       y       -       -       smtpd
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
pickup    unix  n       -       y       60      1       pickup
cleanup   unix  n       -       y       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       y       1000?   1       tlsmgr
rewrite   unix  -       -       y       -       -       trivial-rewrite
bounce    unix  -       -       y       -       0       bounce
defer     unix  -       -       y       -       0       bounce
trace     unix  -       -       y       -       0       bounce
verify    unix  -       -       y       -       1       verify
flush     unix  n       -       y       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
smtp      unix  -       -       y       -       -       smtp
relay     unix  -       -       y       -       -       smtp
showq     unix  n       -       y       -       -       showq
error     unix  -       -       y       -       -       error
retry     unix  -       -       y       -       -       error
discard   unix  -       -       y       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       y       -       -       lmtp
anvil     unix  -       -       y       -       1       anvil
scache    unix  -       -       y       -       1       scache
EOF

    # Stamp empty lookup tables if not already provided via bind-mount.
    [ -e "$rootfs/etc/mail-config/vmailbox" ] || touch "$rootfs/etc/mail-config/vmailbox" 2>/dev/null || true
    [ -e "$rootfs/etc/mail-config/virtual" ] || touch "$rootfs/etc/mail-config/virtual" 2>/dev/null || true

    echo "[install] Postfix configured"
}

# Write dovecot.conf into the LXC rootfs.
configure_dovecot() {
    local container="$1"
    local rootfs="${LXC_BASE:-/var/lib/lxc}/$container/rootfs"
    echo "[install] configuring Dovecot in $rootfs..."

    mkdir -p "$rootfs/etc/dovecot"

    # Sieve n'est disponible QUE si dovecot-sieve/dovecot-managesieved sont
    # installés dans le rootfs cible. Émettre les blocs Sieve sans condition
    # brique Dovecot sur une LXC qui ne les a pas (refus de démarrer, panne
    # mail complète) — cf. #1169 revue finale, defaut bloquant 1.
    local sieve_available=false
    if [ -e "$rootfs/usr/lib/dovecot/modules/lib90_sieve_plugin.so" ] || [ -e "$rootfs/usr/bin/sievec" ]; then
        sieve_available=true
    fi

    if [ "$sieve_available" = "true" ]; then
        cat > "$rootfs/etc/dovecot/dovecot.conf" <<'EOF'
protocols = imap pop3 lmtp sieve
listen = *
mail_location = maildir:/var/vmail/%d/%n
mail_uid = 5000
mail_gid = 5000
first_valid_uid = 500
last_valid_uid = 65534

auth_mechanisms = plain login
passdb {
  driver = passwd-file
  args = /etc/mail-config/users
}
userdb {
  driver = static
  args = uid=5000 gid=5000 home=/var/vmail/%d/%n
}

service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}
service pop3-login {
  inet_listener pop3 {
    port = 110
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}

namespace inbox {
  inbox = yes
  separator = /
}

log_path = /var/log/dovecot.log
info_log_path = /var/log/dovecot.log
EOF
    else
        cat > "$rootfs/etc/dovecot/dovecot.conf" <<'EOF'
protocols = imap pop3 lmtp
listen = *
mail_location = maildir:/var/vmail/%d/%n
mail_uid = 5000
mail_gid = 5000
first_valid_uid = 500
last_valid_uid = 65534

auth_mechanisms = plain login
passdb {
  driver = passwd-file
  args = /etc/mail-config/users
}
userdb {
  driver = static
  args = uid=5000 gid=5000 home=/var/vmail/%d/%n
}

service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}
service pop3-login {
  inet_listener pop3 {
    port = 110
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}

namespace inbox {
  inbox = yes
  separator = /
}

log_path = /var/log/dovecot.log
info_log_path = /var/log/dovecot.log
EOF
    fi

    # SSL-aware : ne JAMAIS régénérer une conf sans TLS si le board sert 993/995.
    # Le cert vit dans $DATA_PATH/ssl et est monté /etc/ssl/mail dans le LXC.
    if [ -f "${DATA_PATH:-/data/volumes/mail}/ssl/fullchain.pem" ]; then
        cat >> "$rootfs/etc/dovecot/dovecot.conf" <<'EOF'
ssl = yes
ssl_cert = </etc/ssl/mail/fullchain.pem
ssl_key = </etc/ssl/mail/privkey.pem
ssl_min_protocol = TLSv1.2
EOF
    else
        echo 'ssl = no' >> "$rootfs/etc/dovecot/dovecot.conf"
    fi

    # Sieve + ManageSieve : filtrage côté serveur (règles utilisateur) et
    # provisioning du script par défaut (Task 6 dépose default.sieve).
    # Gaté sur $sieve_available (cf. plus haut) : un rootfs sans le plugin
    # ne doit voir NI le service managesieve-login NI mail_plugins=...sieve.
    if [ "$sieve_available" = "true" ]; then
        cat >> "$rootfs/etc/dovecot/dovecot.conf" <<'EOF'

protocol lmtp {
  mail_plugins = $mail_plugins sieve
}
service managesieve-login {
  inet_listener sieve {
    port = 4190
  }
}
plugin {
  sieve = file:~/sieve;active=~/.dovecot.sieve
  # sieve_before (et NON sieve_default) : le sieve global (anti-spam → Junk)
  # s'exécute AVANT le script perso de chaque membre, donc il s'applique
  # TOUJOURS — y compris aux membres qui ont créé leurs propres filtres dans le
  # webmail. `sieve_default` n'aurait servi de repli QUE pour les membres SANS
  # filtre perso, désactivant l'anti-spam dès le premier filtre créé (#1181).
  sieve_before = /var/vmail/sieve/default.sieve
}
EOF
    fi

    [ -e "$rootfs/etc/mail-config/users" ] || touch "$rootfs/etc/mail-config/users" 2>/dev/null || true
    chmod 644 "$rootfs/etc/mail-config/users" 2>/dev/null || true

    install_default_sieve "$container"

    echo "[install] Dovecot configured"
}

# Déploie le script Sieve global par défaut (spam Rspamd → Junk, Task 6) dans
# le rootfs de la LXC et le compile via sievec quand le conteneur tourne.
# Idempotent : mkdir -p + cp -f, recompile sans dégât si déjà présent.
install_default_sieve() {
    local container="$1"
    local rootfs="${LXC_BASE:-/var/lib/lxc}/$container/rootfs"
    local sieve_src="${SIEVE_CONFIG_DIR:-/usr/lib/secubox/mail/config/sieve}/default.sieve"

    [ -f "$sieve_src" ] || { echo "install_default_sieve: source $sieve_src missing" >&2; return 0; }

    # /var/vmail est un BIND-MOUNT de $DATA_PATH/vmail quand le conteneur tourne :
    # écrire dans "$rootfs/var/vmail" est alors SHADOWÉ par le montage (le fichier
    # n'apparaît pas dans le conteneur). On vise donc la SOURCE du bind-mount
    # ($DATA_PATH/vmail) quand elle existe (cas gestes runtime), et on retombe sur
    # le rootfs seulement au build (conteneur pas encore monté).
    local vmail_dir="${DATA_PATH:-/data/volumes/mail}/vmail"
    [ -d "$vmail_dir" ] || vmail_dir="$rootfs/var/vmail"
    mkdir -p "$vmail_dir/sieve"
    cp -f "$sieve_src" "$vmail_dir/sieve/default.sieve"
    # OWNERSHIP CRITIQUE (LXC non privilégié). Créé par root-hôte, le dossier
    # appartient à l'uid hôte 0 = « nobody » non mappé dans le conteneur : vmail
    # ne peut alors PAS écrire le .svbin compilé (Pigeonhole abandonne, spam non
    # filtré) et le dossier devient même irrémovable depuis le conteneur. On
    # l'aligne sur le propriétaire (mappé) de $vmail_dir lui-même — c'est l'uid
    # hôte de vmail — pour que le conteneur le voie comme vmail:vmail.
    if own="$(stat -c '%u:%g' "$vmail_dir" 2>/dev/null)" && [ -n "$own" ]; then
        chown -R "$own" "$vmail_dir/sieve" 2>/dev/null || true
    fi

    # Pré-compilation FACULTATIVE : ne l'exécuter que si le conteneur porte
    # déjà `sievec` (dovecot-sieve installé) ET que l'aide `lxc_attach_run` est
    # chargée. Quand cette lib est sourcée seule (par maildir-reconcile, sans
    # lxc.sh), lxc_attach_run est indéfinie — appeler `sievec` échouerait
    # (command not found) sur un conteneur qui, de toute façon, n'a pas encore
    # Sieve. Pigeonhole compile `sieve_before` à la volée à la première
    # remise ; sauter la pré-compilation est sans conséquence fonctionnelle.
    if [ -e "$rootfs/usr/bin/sievec" ] \
        && type lxc_attach_run >/dev/null 2>&1 \
        && lxc_running "$container"; then
        lxc_attach_run "$container" sievec /var/vmail/sieve/default.sieve 2>/dev/null || true
    fi
}

# Write Apache+Roundcube config inside the LXC rootfs. Phase 1 mirrors what
# the board has today; Phase 5 may migrate to nginx+php-fpm.
configure_roundcube() {
    local container="$1"
    local rootfs="${LXC_BASE:-/var/lib/lxc}/$container/rootfs"
    local domain="${DOMAIN:-secubox.local}"
    echo "[install] configuring Roundcube (Apache) in $rootfs..."

    mkdir -p "$rootfs/etc/apache2/sites-available" "$rootfs/etc/apache2/sites-enabled"

    cat > "$rootfs/etc/apache2/sites-available/roundcube.conf" <<EOF
<VirtualHost *:80>
    ServerName webmail.${domain}
    DocumentRoot /var/lib/roundcube/public_html
    <Directory /var/lib/roundcube/public_html>
        Options +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog \${APACHE_LOG_DIR}/roundcube_error.log
    CustomLog \${APACHE_LOG_DIR}/roundcube_access.log combined
</VirtualHost>
EOF

    chroot "$rootfs" /bin/bash <<'CHROOT_EOF'
a2dissite 000-default 2>/dev/null || true
a2ensite roundcube
a2enmod php8.2 rewrite 2>/dev/null || true
CHROOT_EOF

    # SQLite backend + local Dovecot/Postfix (issue #152). The Debian Roundcube
    # default (debian-db.php) points at MySQL on :3306, but there is no MariaDB
    # in this LXC → "Internal Error" page. Override via config.inc.php.local
    # (included last, so it wins), init the SQLite schema, and relax TLS verify
    # for the LXC's self-signed Dovecot/Postfix cert. Mirrors the verified live
    # gk2 hotfix; idempotent.
    chroot "$rootfs" /bin/bash <<'CHROOT_EOF'
set -e
mkdir -p /var/lib/roundcube/db
DESKEY="$(openssl rand -base64 24 2>/dev/null || head -c18 /dev/urandom | base64)"
cat > /etc/roundcube/config.inc.php.local <<LOCAL
<?php
// SecuBox :: Roundcube SQLite + local mail (issue #152). Included last so it
// overrides the dbconfig-common MySQL default in debian-db.php.
\$config['db_dsnw'] = 'sqlite:////var/lib/roundcube/db/sqlite.db?mode=0640';
\$config['imap_host'] = 'tls://localhost';
\$config['smtp_host'] = 'tls://localhost';
\$config['des_key'] = '${DESKEY}';
# Le domaine est AJOUTE AUX IDENTIFIANTS NUS (#1014). Sans lui, un operateur
# qui saisit « gk2 » envoie « gk2 » a Dovecot, qui ne connait que
# « gk2@secubox.in » : la connexion echoue et le webmail parait casse.
# La valeur vient de ce que Postfix SERT reellement, pas du domaine declare —
# les deux divergent sur gk2 (declare gk2.secubox.in, servi secubox.in).
\$config['username_domain'] = '$(postconf -h virtual_mailbox_domains 2>/dev/null | tr "," " " | awk "{print \$1}")';
\$config['imap_conn_options'] = array('ssl' => array('verify_peer' => false, 'verify_peer_name' => false));
\$config['smtp_conn_options'] = array('ssl' => array('verify_peer' => false, 'verify_peer_name' => false));
# DUREE DE SESSION (#1335). Le defaut Roundcube est 10 MINUTES : ouverte depuis
# le cardlet du Hall, la session du webmail expirait presque aussitot. On la
# porte a 8 h — une journee de travail — sans toucher a defaults.inc.php, que
# la mise a jour du paquet roundcube reecrirait.
\$config['session_lifetime'] = 480;
LOCAL
if [ -f /etc/roundcube/config.inc.php ] && ! grep -q "config.inc.php.local" /etc/roundcube/config.inc.php; then
    echo "include_once('/etc/roundcube/config.inc.php.local');" >> /etc/roundcube/config.inc.php
fi
if [ ! -f /var/lib/roundcube/db/sqlite.db ] && [ -f /usr/share/dbconfig-common/data/roundcube/install/sqlite3 ]; then
    sqlite3 /var/lib/roundcube/db/sqlite.db < /usr/share/dbconfig-common/data/roundcube/install/sqlite3
fi
chown -R www-data:www-data /var/lib/roundcube/db
chmod 0640 /var/lib/roundcube/db/sqlite.db 2>/dev/null || true
CHROOT_EOF

    echo "[install] Roundcube (Apache) configured"
}
