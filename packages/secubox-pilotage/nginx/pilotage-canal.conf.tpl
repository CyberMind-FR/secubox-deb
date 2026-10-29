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
#
# __IP__ et __SOURCE__ sont substitués par secubox-pilotage-ecoute.
server {
    listen __IP__:8472;
    server_name _;

    allow __SOURCE__;
    deny all;

    client_max_body_size 256k;

    location /canal/v1/ {
        proxy_pass http://unix:/run/secubox/pilotage-canal.sock;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host localhost;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        client_max_body_size 256k;
        # Le sondage long de l'agent attend jusqu'à 25 s : 60 s laissent de la marge sans retenir une connexion morte.
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
        proxy_buffering off;
    }

    location / { return 403; }
}
