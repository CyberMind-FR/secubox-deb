# /etc/nginx/conf.d/p2p-macro-mesh.conf — rendered by secubox-p2p postinst.
#
# Gondwana mesh-internal P2P macro grant endpoint. Consumer nodes on the
# wg-mesh (10.10.0.0/24) pull macro credentials from their approved provider:
#   * POST /api/v1/p2p-macro/grant/<service_id> — consumer presents its
#     self-signed Subscription; provider verifies self-certifyingly + runs
#     sudo macroctl <kind> grant (§4.4 of 2026-06-30-macro-subsystem-tor-exit-design.md).
#
# Exposure is deliberately minimal (CSPN: minimal attack surface):
#   * binds ONLY the node's wg-mesh address (__MESH_IP__), never 0.0.0.0
#   * allow 10.10.0.0/24 + deny all — non-mesh sources are refused at nginx
#     before the request reaches the UNIX socket
#   * X-Real-IP is set to $remote_addr so the grant endpoint sees the
#     provider-observed mesh source IP (used as --src-ip to macroctl) — the
#     consumer cannot forge a different IP
#   * port 8798 (one below the annuaire mesh listener at 8799)
#
# __MESH_IP__ is substituted by postinst with the detected wg-mesh IPv4. If no
# wg-mesh interface exists, postinst does NOT install this file (no listener).
server {
    listen __MESH_IP__:8798;
    server_name _;

    allow 10.10.0.0/24;
    deny all;

    # Macro grant surface — prefix match covers /grant/<service_id> slugs.
    location ~ ^/api/v1/p2p-macro/ {
        proxy_pass http://unix:/run/secubox/p2p.sock;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 20s;
        proxy_send_timeout 20s;
        proxy_intercept_errors on;
    }

    location / { return 403; }
}
