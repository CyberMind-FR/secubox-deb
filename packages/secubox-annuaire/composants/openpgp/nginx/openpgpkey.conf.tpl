# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# WKD — Web Key Directory de @DOMAINE@ (#1738), méthode « avancée » :
#   https://openpgpkey.@DOMAINE@/.well-known/openpgpkey/@DOMAINE@/hu/<hash>?l=<local>
# Généré par le postinst de secubox-openpgp ; HAProxy → sbxwaf → ici (:9080).
# Le démon ne sert que les adresses que la box a CONFIÉES à leur personne.
server {
    listen 9080;
    server_name openpgpkey.@DOMAINE@;

    location ^~ /.well-known/acme-challenge/ { root /usr/share/secubox/www; try_files $uri =404; }

    location ~ "^/\.well-known/openpgpkey/([a-z0-9.-]+)/hu/([ybndrfg8ejkmcpqxot1uwisza345h769]{32})$" {
        limit_except GET { deny all; }
        rewrite ^/\.well-known/openpgpkey/([a-z0-9.-]+)/hu/(.+)$ /wkd/$1/hu/$2 break;
        proxy_pass http://unix:/run/secubox/openpgp.sock;
        proxy_set_header Host $host;
        proxy_set_header X-SecuBox-Maillage "";
        proxy_set_header X-Real-IP       $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 10s;
    }
    location ~ ^/\.well-known/openpgpkey/([a-z0-9.-]+)/policy$ {
        limit_except GET { deny all; }
        rewrite ^/\.well-known/openpgpkey/([a-z0-9.-]+)/policy$ /wkd/$1/policy break;
        proxy_pass http://unix:/run/secubox/openpgp.sock;
        proxy_set_header Host $host;
        proxy_set_header X-SecuBox-Maillage "";
        proxy_read_timeout 10s;
    }
    location / { return 404; }
}
