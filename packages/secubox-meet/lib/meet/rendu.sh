#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: secubox-meet :: rendu.sh
#
# Bibliothèque SOURCÉE par install-lxc.sh (et par les tests) : elle ne fait
# rien à l'inclusion, elle définit seulement `rendre_tout`. Séparer le rendu du
# provisionnement permet de le vérifier sans conteneur ni root : on lit les
# fichiers produits, on n'imite pas des appels.
#
# Entrée (variables d'environnement) :
#   MEET_DOMAIN LIVEKIT_DOMAIN LXC_IP MEET_ISSUER
#   DJANGO_SECRET_KEY DB_PASSWORD LIVEKIT_SECRET
#   OIDC_CLIENT_SECRET (vide admis : il est posé plus tard par `meetctl oidc`)
#   LXC_NAME LXC_PATH LXC_BRIDGE LXC_GW (défauts : meet, /data/lxc, br-lxc, 10.100.0.1)

# Un nom DNS, rien d'autre : il est écrit tel quel dans meet.env et dans
# nginx-meet.conf (un « ; » ou un saut de ligne y injecterait une directive).
_domaine_valide() {
    [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]
}

_exiger() {
    local nom
    for nom in "$@"; do
        [ -n "${!nom:-}" ] || { printf '[rendu] variable %s manquante\n' "$nom" >&2; return 1; }
    done
}

rendre_livekit_yaml() {
    cat > "$1/livekit.yaml" <<YAML
port: 7880
bind_addresses: ["0.0.0.0"]
rtc:
  tcp_port: 7881
  udp_port: 7882
  use_external_ip: true
redis:
  address: 127.0.0.1:6379
keys:
  meet: ${LIVEKIT_SECRET}
webhook:
  api_key: meet
  urls: ["http://127.0.0.1:80/api/v1.0/rooms/webhooks-livekit/"]
logging:
  level: info
YAML
}

# Fichier KEY=VALUE simple, lu par systemd (EnvironmentFile) : une variable par
# ligne, sans `export`. OIDC_OP_LOGOUT_ENDPOINT est absent à dessein (laissé
# vide par Meet : la déconnexion se fait côté Meet seulement).
rendre_meet_env() {
    cat > "$1/meet.env" <<ENV
DJANGO_SETTINGS_MODULE=meet.settings
DJANGO_CONFIGURATION=Production
PYTHONPATH=/opt/meet/src/src/backend
DJANGO_SECRET_KEY=${DJANGO_SECRET_KEY}
DJANGO_ALLOWED_HOSTS=${MEET_DOMAIN}
DJANGO_CSRF_TRUSTED_ORIGINS=https://${MEET_DOMAIN}
DJANGO_LANGUAGE_CODE=fr-fr
MEET_BASE_URL=https://${MEET_DOMAIN}
DATA_DIR=/var/lib/meet
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=meet
DB_USER=meet
DB_PASSWORD=${DB_PASSWORD}
REDIS_URL=redis://127.0.0.1:6379/1
CELERY_TASK_ALWAYS_EAGER=True
ALLOW_UNREGISTERED_ROOMS=False
RESOURCE_DEFAULT_ACCESS_LEVEL=public
OIDC_RP_CLIENT_ID=meet
OIDC_RP_CLIENT_SECRET=${OIDC_CLIENT_SECRET:-}
OIDC_OP_JWKS_ENDPOINT=${MEET_ISSUER}/jwks
OIDC_OP_AUTHORIZATION_ENDPOINT=${MEET_ISSUER}/authorize
OIDC_OP_TOKEN_ENDPOINT=${MEET_ISSUER}/token
OIDC_OP_USER_ENDPOINT=${MEET_ISSUER}/userinfo
OIDC_RP_SIGN_ALGO=RS256
OIDC_RP_SCOPES="openid email"
OIDC_USE_PKCE=True
OIDC_PKCE_CODE_CHALLENGE_METHOD=S256
OIDC_USE_NONCE=True
OIDC_REDIRECT_REQUIRE_HTTPS=True
OIDC_USERINFO_FULLNAME_FIELDS=name
OIDC_USERINFO_SHORTNAME_FIELD=nickname
LOGIN_REDIRECT_URL=https://${MEET_DOMAIN}
LOGIN_REDIRECT_URL_FAILURE=https://${MEET_DOMAIN}
LOGOUT_REDIRECT_URL=https://${MEET_DOMAIN}
LIVEKIT_API_KEY=meet
LIVEKIT_API_SECRET=${LIVEKIT_SECRET}
LIVEKIT_API_URL=https://${LIVEKIT_DOMAIN}
LIVEKIT_INTERNAL_URL=http://127.0.0.1:7880
LIVEKIT_VERIFY_SSL=True
FRONTEND_IS_SILENT_LOGIN_ENABLED=True
ENV
}

# nginx INTERNE du conteneur (port 80) : l'hôte (HAProxy -> sbxwaf -> nginx)
# termine TLS. Le schéma vu par Django vient de l'en-tête de l'hôte, https par
# défaut s'il manque (sinon Django croit être en http et refuse les cookies sûrs).
#
# Le webhook de LiveKit (même conteneur) passe AUSSI par ce nginx : posté en
# direct sur gunicorn, avec « Host: 127.0.0.1:8000 » et sans X-Forwarded-Proto,
# Django le refuserait (DisallowedHost, 400) ou le redirigerait vers https.
# Ici l'hôte public (celui de DJANGO_ALLOWED_HOSTS) et https sont posés, et seul
# 127.0.0.1 y a accès.
rendre_nginx() {
    local modele
    modele=$(cat <<'NGINX'
map $http_x_forwarded_proto $meet_schema {
    default $http_x_forwarded_proto;
    ""      https;
}

server {
    listen 80 default_server;
    server_name _;
    client_max_body_size 50m;

    root /opt/meet/frontend;

    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $meet_schema;

    location = /api/v1.0/rooms/webhooks-livekit/ {
        allow 127.0.0.1;
        deny all;
        proxy_set_header Host @MEET_DOMAIN@;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_pass http://127.0.0.1:8000;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000;
    }

    location /admin/ {
        proxy_pass http://127.0.0.1:8000;
    }

    location /static/ {
        alias /var/lib/meet/static/;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
NGINX
)
    printf '%s\n' "${modele//@MEET_DOMAIN@/$MEET_DOMAIN}" > "$1/nginx-meet.conf"
}

rendre_unites() {
    cat > "$1/meet-backend.service" <<'UNIT'
[Unit]
Description=La Suite Meet - backend Django (gunicorn)
After=postgresql.service redis-server.service

[Service]
Type=simple
User=meet
Group=meet
EnvironmentFile=/etc/meet/meet.env
WorkingDirectory=/opt/meet/src/src/backend
ExecStart=/opt/meet/venv/bin/gunicorn -b 127.0.0.1:8000 -w 2 --timeout 90 meet.wsgi:application
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
    cat > "$1/livekit.service" <<'UNIT'
[Unit]
Description=LiveKit - serveur média WebRTC
After=redis-server.service

[Service]
Type=simple
User=livekit
Group=livekit
ExecStart=/usr/local/bin/livekit-server --config /etc/livekit/livekit.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
}

# Configuration LXC (écrite par l'hôte). Le décalage idmap du rootfs est fait
# par install-lxc.sh, pas ici : ce fichier ne décrit que le conteneur.
rendre_lxc_config() {
    local nom="${LXC_NAME:-meet}" chemin="${LXC_PATH:-/data/lxc}"
    cat > "$1/lxc-config" <<LXC
# SecuBox-managed - voir secubox-meet / install-lxc.sh
lxc.uts.name = ${nom}
lxc.net.0.type = veth
lxc.net.0.link = ${LXC_BRIDGE:-br-lxc}
lxc.net.0.flags = up
lxc.net.0.ipv4.address = ${LXC_IP}/24
lxc.net.0.ipv4.gateway = ${LXC_GW:-10.100.0.1}
lxc.net.0.name = eth0
lxc.rootfs.path = dir:${chemin}/${nom}/rootfs
lxc.include = /usr/share/lxc/config/common.conf
lxc.idmap = u 0 100000 65536
lxc.idmap = g 0 100000 65536
lxc.apparmor.profile = generated
lxc.cgroup2.memory.max = 2147483648
lxc.start.auto = 1
lxc.start.delay = 5
LXC
}

rendre_tout() {
    local sortie="${1:-}"
    [ -n "$sortie" ] || { echo "[rendu] dossier de sortie manquant" >&2; return 1; }
    _exiger MEET_DOMAIN LIVEKIT_DOMAIN LXC_IP MEET_ISSUER DJANGO_SECRET_KEY DB_PASSWORD LIVEKIT_SECRET || return 1
    local d
    for d in "$MEET_DOMAIN" "$LIVEKIT_DOMAIN"; do
        _domaine_valide "$d" || { printf '[rendu] domaine invalide : %q\n' "$d" >&2; return 1; }
    done
    install -d -m 0700 "$sortie"
    rendre_livekit_yaml "$sortie"
    rendre_meet_env "$sortie"
    rendre_nginx "$sortie"
    rendre_unites "$sortie"
    rendre_lxc_config "$sortie"
    # meet.env et livekit.yaml portent des secrets.
    chmod 0600 "$sortie/meet.env" "$sortie/livekit.yaml"
}
