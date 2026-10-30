# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# /etc/nginx/conf.d/secubox-pilotage-canal.conf — rendu par secubox-pilotage-ecoute (#3126), un « server » par IP de tunnel PRÉSENTE.
#
# Canal des box : l'agent de chaque box se connecte en SORTIE à 10.10.0.1:8472 (wg-mesh) ou 10.64.0.1:8472 (wg-autoload).
# Exposition minimale :
#   * écoute sur l'IP du tunnel seulement, jamais 0.0.0.0 ni un port nu ;
#   * source limitée au réseau du tunnel (allow/deny) ; la règle nft (iifname + saddr) double ce filtre ;
#   * une seule famille de routes, /canal/v1/, vers la socket du canal ; la socket d'administration n'est JAMAIS atteignable ici ;
#   * X-Real-IP = adresse source de la connexion, posée par nginx : tout en-tête envoyé par le client est écrasé (R16). C'est l'identité
#     de la box (WireGuard ne laisse passer d'un pair que sa propre adresse) ; l'application ne la lit que sur cette socket Unix.
#   * le module realip HÉRITÉ est neutralisé (C1) : secubox-hub règle au niveau http « real_ip_header X-Forwarded-For; real_ip_recursive on; »
#     et secubox-realip fait confiance à 10.10.0.1 et 10.64.0.1 (nos propres adresses) ; un processus local joignant l'écouteur avec un
#     X-Forwarded-For forgé verrait sinon $remote_addr réécrit, donc l'identité de n'importe quelle box usurpée. D'où set_real_ip_from
#     255.255.255.255 (adresse impossible : la liste héritée est remplacée, rien n'est de confiance ici) et $realip_remote_addr, qui est
#     toujours l'adresse du pair TCP.
#   * 4 connexions simultanées par adresse (limit_conn ; la zone est déclarée une fois en tête du fichier rendu).
#   * X-SecuBox-Pilotage-Tunnel: 1 (L2, M6) : posé ICI SEULEMENT, il dit « passée par l'écouteur du tunnel » ; secubox-proxy.conf le vide sur tout
#     autre proxy et l'agrégateur ne relaie jamais vers la socket du canal. Le canal refuse (403, audité) une requête qui ne le porte pas.
#
# __IP__ et __SOURCE__ sont substitués par secubox-pilotage-ecoute.
server {
    listen __IP__:8472;
    server_name _;

    set_real_ip_from 255.255.255.255;
    real_ip_recursive off;

    allow __SOURCE__;
    deny all;

    limit_conn pilotage_canal 4;
    limit_conn_status 429;

    client_max_body_size 256k;

    location /canal/v1/ {
        proxy_pass http://unix:/run/secubox/pilotage-canal.sock;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host localhost;
        proxy_set_header X-Real-IP $realip_remote_addr;
        proxy_set_header X-Forwarded-For $realip_remote_addr;
        proxy_set_header X-SecuBox-Pilotage-Tunnel 1;
        client_max_body_size 256k;
        # Le sondage long de l'agent attend jusqu'à 25 s : 60 s laissent de la marge sans retenir une connexion morte.
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
        proxy_buffering off;
    }

    location / { return 403; }
}
