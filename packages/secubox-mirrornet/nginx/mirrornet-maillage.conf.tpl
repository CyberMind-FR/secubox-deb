# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# MirrorNet (#3653) — objets des jeux de données servis aux pairs, inclus dans l'écouteur maillé :8799 de l'annuaire
# (10.10.0.0/24 seulement). Rendu par le postinst dans /etc/nginx/secubox-mesh.d/mirrornet.conf (root, 0600) :
# __PREUVE__ est le secret de /etc/secubox/secrets/mirrornet/pair.preuve, que seul nginx pose. MirrorNet ne sert un
# objet qu'avec cette preuve, l'adresse du pair posée ici, et un abonnement Actif de ce pair.
location ^~ /mirrornet/objets/ {
    rewrite "^/mirrornet/objets/(b2:[0-9a-f]{64})$" /pair/objets/$1 last;
    return 404;
}
location ^~ /pair/objets/ {
    internal;
    limit_except GET { deny all; }
    proxy_pass http://unix:/run/secubox/mirrornet.sock;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header Connection "";
    proxy_set_header Authorization "";
    proxy_set_header Cookie "";
    proxy_set_header X-SecuBox-Pair-IP $remote_addr;
    proxy_set_header X-SecuBox-Pair-Preuve "__PREUVE__";
    proxy_buffering off;
    proxy_max_temp_file_size 0;
    proxy_read_timeout 300s;
}
# #3661 — preuve de possession demandée par le producteur à l'espace qui garde une copie de son jeu.
location ^~ /mirrornet/preuve/ {
    rewrite "^/mirrornet/preuve/(b2:[0-9a-f]{64})$" /pair/preuve/$1 last;
    return 404;
}
location ^~ /pair/preuve/ {
    internal;
    limit_except GET { deny all; }
    proxy_pass http://unix:/run/secubox/mirrornet.sock;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header Connection "";
    proxy_set_header Authorization "";
    proxy_set_header Cookie "";
    proxy_set_header X-SecuBox-Pair-IP $remote_addr;
    proxy_set_header X-SecuBox-Pair-Preuve "__PREUVE__";
    proxy_read_timeout 120s;
}
