# /etc/nginx/conf.d/annuaire-mesh.conf — rendered by secubox-annuaire postinst.
#
# Gondwana mesh-internal Annuaire federation endpoint. Peer nodes on the
# wg-mesh (10.10.0.0/24) pull signed, self-certifying directory data from here:
#   * /api/v1/annuaire/services    — service offers (#766)
#   * /api/v1/annuaire/log/export  — the full signed directory log for
#     replication (#768): peers + config blobs + offers. Every entry is
#     Ed25519-signed and self-certifying (did_from_pubkey == author), so the
#     reader verifies without trusting this listener; nothing secret is carried.
#   * /api/v1/annuaire/noeud/adresses — this node's {boxname, mesh_ip, lan_ip}
#     (#1556), a static file for the master's <box>.lan/.mesh names.
#   * /api/v1/annuaire/fleet/self  — this node's own signed MetricSnapshot
#     (fleet-metrics, Task 5): the same public, no-JWT, self-certifying record
#     a peer's /fleet view pulls to render the fleet-wide dashboard.
#
# Exposure is deliberately minimal (CSPN: minimal attack surface):
#   * binds ONLY the node's wg-mesh address (__MESH_IP__), never 0.0.0.0
#   * accepts GET on the exact read paths below, and POST on ONE path only
#     (the OpenPGP drop box, #1736)
#   * allow 10.10.0.0/24 + deny all — non-mesh sources are refused
#   * the data it serves is public, signed, self-certifying. ONE write path
#     exists (#1736): the OpenPGP inter-box drop box, POST only, 256 KiB max —
#     it accepts only a message signed by a peer's BOUND key and encrypted for
#     this box; the openpgp daemon verifies everything, nginx only bounds it.
#
# __MESH_IP__ is substituted by postinst with the detected wg-mesh IPv4. If no
# wg-mesh interface exists, postinst does NOT install this file (no listener).
server {
    listen __MESH_IP__:8799;
    server_name _;

    allow 10.10.0.0/24;
    deny all;

    # Read-only federation pull surface — these three exact paths, nothing else.
    location = /api/v1/annuaire/services {
        limit_except GET { deny all; }
        rewrite ^/api/v1/annuaire/(.*)$ /$1 break;
        proxy_pass http://unix:/run/secubox/annuaire.sock;
        include /etc/nginx/snippets/secubox-proxy.conf;
        # Pair du maillage (#1530) : lecture publique des enregistrements SIGNÉS
        # (le lecteur vérifie) ; l'écouteur n'accepte que 10.10.0.0/24.
        proxy_set_header X-SecuBox-Maillage 1;
        proxy_intercept_errors on;
    }

    # Full signed directory log for cross-node replication (#768).
    location = /api/v1/annuaire/log/export {
        limit_except GET { deny all; }
        rewrite ^/api/v1/annuaire/(.*)$ /$1 break;
        proxy_pass http://unix:/run/secubox/annuaire.sock;
        include /etc/nginx/snippets/secubox-proxy.conf;
        # Pair du maillage (#1530) : lecture publique des enregistrements SIGNÉS
        # (le lecteur vérifie) ; l'écouteur n'accepte que 10.10.0.0/24.
        proxy_set_header X-SecuBox-Maillage 1;
        proxy_intercept_errors on;
    }

    # This node's own signed MetricSnapshot for fleet-wide dashboards (Task 5,
    # feat/fleet-metrics): mirrors /log/export verbatim — public, no-JWT,
    # self-certifying — the exact path _fetch_fleet_peer() pulls from peers.
    location = /api/v1/annuaire/fleet/self {
        limit_except GET { deny all; }
        rewrite ^/api/v1/annuaire/(.*)$ /$1 break;
        proxy_pass http://unix:/run/secubox/annuaire.sock;
        include /etc/nginx/snippets/secubox-proxy.conf;
        # Pair du maillage (#1530) : lecture publique des enregistrements SIGNÉS
        # (le lecteur vérifie) ; l'écouteur n'accepte que 10.10.0.0/24.
        proxy_set_header X-SecuBox-Maillage 1;
        proxy_intercept_errors on;
    }

    # Adresses de CETTE box pour les noms <box>.lan/.mesh.<zone> (#1556) : un
    # fichier statique écrit par secubox-annuaire-noms ({boxname, node_id,
    # mesh_ip, lan_ip}). Non signé — la confiance vient de WireGuard : seule la
    # box qui détient cette adresse du maillage peut répondre sur elle.
    location = /api/v1/annuaire/noeud/adresses {
        limit_except GET { deny all; }
        default_type application/json;
        alias /var/lib/secubox/annuaire/adresses.json;
    }

    # DÉPÔT OPENPGP INTER-BOX (#1736) — la seule route d'écriture de cette
    # écoute. Un message signé ET chiffré pour cette box ; le démon vérifie
    # tout (signataire = clé liée à l'expéditeur dans l'annuaire, destinataire,
    # fraîcheur, rejeu). nginx ne fait que borner : POST, 256 Kio.
    location = /api/v1/openpgp/boite/depot {
        limit_except POST { deny all; }
        client_max_body_size 256k;
        rewrite ^/api/v1/openpgp/(.*)$ /$1 break;
        proxy_pass http://unix:/run/secubox/openpgp.sock;
        include /etc/nginx/snippets/secubox-proxy.conf;
        proxy_set_header X-SecuBox-Maillage 1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_intercept_errors on;
    }

    location / { return 403; }
}
