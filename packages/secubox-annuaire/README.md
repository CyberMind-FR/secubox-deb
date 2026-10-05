<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-annuaire

SecuBox Annuaire-Miroir — federated self-certifying trust substrate.

The Annuaire-Miroir is the trust directory for SecuBox-DEB, providing a BLAKE2b-chained, CONIKS-style append-only audit journal with four protocols: AUTO-ADD (provisional discovery), INVITE (capability-based membership), PROPOSAL (anti-plutocratic governance), and EMANCIPATE (staged anchor removal). All objects are Ed25519-signed, RFC 3339-timestamped, and access-gated by the can() resolver. Served on /run/secubox/annuaire.sock, JWT-gated.

Paquet Debian : version `0.10.13-1~bookworm1`, architecture `all`.

## Contenu

- `annuaire/` : fichiers du module
- `api/` : API FastAPI
- `conf/` : configuration livrée
- `menu.d/` : entrée de menu
- `nginx/` : route nginx
- `sbin/` : exécutables
- `sysctl/` : fichiers du module
- `systemd/` : unités systemd
- `tests/` : tests
- `www/` : interface web

## Exécution

Socket Unix : `/run/secubox/annuaire.sock`, `/run/secubox/openpgp.sock`.
- `secubox-annuaire-apply.service` : SecuBox Annuaire — apply replicated config via 4R (gondwana P2, #768), lance `annuairectl`
- `secubox-annuaire-apply.timer` : SecuBox Annuaire — periodic config apply (gondwana P2, #768)
- `secubox-annuaire-bans-apply.service` : SecuBox Annuaire — enforce the federated ban union into nft (#768), lance `annuairectl`
- `secubox-annuaire-bans-apply.timer` : SecuBox Annuaire — periodic threatmesh ban enforcement (#768)
- `secubox-annuaire-noms.service` : SecuBox — la box se fait connaître : Bonjour + noms <box>.lan/.mesh (#1556), lance `secubox-annuaire-noms`
- `secubox-annuaire-noms.timer` : SecuBox — rafraîchir l'annonce Bonjour et les noms du maillage (#1556)
- `secubox-annuaire.service` : SecuBox Annuaire-Miroir — federated trust substrate API (utilisateur `secubox`), lance `python3`
- `secubox-metrics-publish.service` : SecuBox Annuaire — publish this node's signed fleet metrics snapshot (fleet-metrics) (utilisateur `secubox`), lance `sbx-fleetctl`
- `secubox-metrics-publish.timer` : SecuBox Annuaire — periodic fleet metrics publish (fleet-metrics)

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/health` | aucune |
| `GET` | `/status` | require_lecture |
| `GET` | `/log` | require_lecture |
| `GET` | `/verify-chain` | require_lecture |
| `GET` | `/merkle-root` | require_lecture |
| `GET` | `/can` | require_lecture |
| `GET` | `/proposal/{proposal_id}` | require_lecture |
| `POST` | `/auto-add` | require_jwt |
| `POST` | `/invite` | require_jwt |
| `POST` | `/join` | require_jwt |
| `POST` | `/proposal` | require_jwt |
| `POST` | `/proposal/{proposal_id}/vote` | require_jwt |
| `POST` | `/revoke` | require_jwt |
| `POST` | `/emancipate` | require_jwt |
| `GET` | `/services` | aucune |
| `POST` | `/service/offer` | require_jwt |
| `POST` | `/service/{service_id}/revoke` | require_jwt |
| `POST` | `/service/{service_id}/subscribe` | require_jwt |
| `GET` | `/subscriptions` | require_lecture |
| `POST` | `/subscription/{subscription_id}/approve` | require_jwt |
| `POST` | `/subscription/{subscription_id}/reject` | require_jwt |
| `POST` | `/services/pull` | require_jwt |
| `GET` | `/nodes` | require_lecture |
| `GET` | `/config` | require_lecture |
| `GET` | `/bans` | require_lecture |
| `GET` | `/log/export` | aucune |
| `POST` | `/node/publish` | require_jwt |
| `POST` | `/config/publish` | require_jwt |
| `POST` | `/config/revoke` | require_jwt |
| `POST` | `/log/pull` | require_jwt |
| `GET` | `/fleet/self` | aucune |
| `GET` | `/fleet` | require_jwt |
| `GET` | `/centers` | require_lecture |
| `GET` | `/centers/ownership` | require_lecture |
| `GET` | `/centers/proposals` | require_lecture |
| `GET` | `/centers/effective/{scope}` | require_lecture |
| `POST` | `/centers/grant` | require_jwt |
| `POST` | `/centers/revoke` | require_jwt |
| `POST` | `/centers/proposal/accept` | require_jwt |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-core`.

## Tests

45 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-annuaire`.
