# /etc/nginx/conf.d/annuaire-mesh.conf — rendered by secubox-annuaire postinst.
#
# Gondwana mesh-internal Annuaire federation endpoint. Peer nodes on the
# wg-mesh (10.10.0.0/24) pull signed, self-certifying service offers from here.
#
# Exposure is deliberately minimal (CSPN: minimal attack surface):
#   * binds ONLY the node's wg-mesh address (__MESH_IP__), never 0.0.0.0
#   * accepts ONLY GET, ONLY the exact path /api/v1/annuaire/services
#   * allow 10.10.0.0/24 + deny all — non-mesh sources are refused
#   * the offers it serves are public, signed, self-certifying data; no
#     mutating endpoint is reachable over the mesh.
#
# __MESH_IP__ is substituted by postinst with the detected wg-mesh IPv4. If no
# wg-mesh interface exists, postinst does NOT install this file (no listener).
server {
    listen __MESH_IP__:8799;
    server_name _;

    allow 10.10.0.0/24;
    deny all;

    # Read-only federation pull surface — nothing else.
    location = /api/v1/annuaire/services {
        limit_except GET { deny all; }
        rewrite ^/api/v1/annuaire/(.*)$ /$1 break;
        proxy_pass http://unix:/run/secubox/annuaire.sock;
        include /etc/nginx/snippets/secubox-proxy.conf;
        proxy_intercept_errors on;
    }

    location / { return 403; }
}
