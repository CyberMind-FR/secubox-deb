# /etc/nginx/conf.d/annuaire-mesh.conf — rendered by secubox-annuaire postinst.
#
# Gondwana mesh-internal Annuaire federation endpoint. Peer nodes on the
# wg-mesh (10.10.0.0/24) pull signed, self-certifying directory data from here:
#   * /api/v1/annuaire/services    — service offers (#766)
#   * /api/v1/annuaire/log/export  — the full signed directory log for
#     replication (#768): peers + config blobs + offers. Every entry is
#     Ed25519-signed and self-certifying (did_from_pubkey == author), so the
#     reader verifies without trusting this listener; nothing secret is carried.
#
# Exposure is deliberately minimal (CSPN: minimal attack surface):
#   * binds ONLY the node's wg-mesh address (__MESH_IP__), never 0.0.0.0
#   * accepts ONLY GET, ONLY the two exact read paths below
#   * allow 10.10.0.0/24 + deny all — non-mesh sources are refused
#   * the data it serves is public, signed, self-certifying; no mutating
#     endpoint is reachable over the mesh.
#
# __MESH_IP__ is substituted by postinst with the detected wg-mesh IPv4. If no
# wg-mesh interface exists, postinst does NOT install this file (no listener).
server {
    listen __MESH_IP__:8799;
    server_name _;

    allow 10.10.0.0/24;
    deny all;

    # Read-only federation pull surface — these two exact paths, nothing else.
    location = /api/v1/annuaire/services {
        limit_except GET { deny all; }
        rewrite ^/api/v1/annuaire/(.*)$ /$1 break;
        proxy_pass http://unix:/run/secubox/annuaire.sock;
        include /etc/nginx/snippets/secubox-proxy.conf;
        proxy_intercept_errors on;
    }

    # Full signed directory log for cross-node replication (#768).
    location = /api/v1/annuaire/log/export {
        limit_except GET { deny all; }
        rewrite ^/api/v1/annuaire/(.*)$ /$1 break;
        proxy_pass http://unix:/run/secubox/annuaire.sock;
        include /etc/nginx/snippets/secubox-proxy.conf;
        proxy_intercept_errors on;
    }

    location / { return 403; }
}
